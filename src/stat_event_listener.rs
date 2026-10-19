// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
// SPDX-License-Identifier: Apache-2.0

//! Story - App listens to Bus `stat-pipeline` stream events.
//!
//! The Stat pipeline emits `sentin8:stat.aggregate.updated` events on the Bus
//! `stat-pipeline` stream family when an analytics aggregate is updated.
//! App listens for these events to surface app-usage metrics on the App
//! Store listing.
//!
//! See (Integration Points).

use std::time::Duration;

use futures_util::StreamExt;
use sentin8::bus::contracts::Message;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Reconnect delay when the Bus SSE connection drops.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// The Bus stream family for Stat pipeline events.
pub const STREAM_FAMILY: &str = "stat-pipeline";

/// The consumer group App uses when subscribing to the Stat pipeline.
pub const CONSUMER_GROUP: &str = "app-listing-metrics";

/// Event types emitted on the `stat-pipeline` stream.
pub const EVENT_AGGREGATE_UPDATED: &str = "sentin8:stat:aggregate:updated";

/// A parsed `sentin8:stat.aggregate.updated` event payload from the Stat pipeline.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AggregateUpdatedEvent {
    /// The Stat property ID the aggregate belongs to.
    pub property_id: Uuid,
    /// The aggregate name (e.g. `pageviews`, `events`, `conversions`).
    pub aggregate: String,
    /// The aggregation window (e.g. `daily`, `hourly`).
    pub window: String,
    /// The bucket start timestamp (RFC 3339).
    pub bucket_start: String,
    /// The metric value for the bucket.
    pub value: f64,
    /// Optional dimension tags associated with the aggregate.
    #[serde(default)]
    pub dimensions: serde_json::Value,
}

/// Parse a Bus message into an `AggregateUpdatedEvent`.
///
/// Returns `Err` if the message is not an `sentin8:stat.aggregate.updated` event or if the
/// payload cannot be deserialized.
pub fn parse_aggregate_updated(msg: &Message) -> Result<AggregateUpdatedEvent, String> {
    if msg.event_type != EVENT_AGGREGATE_UPDATED {
        return Err(format!(
            "unexpected event_type: expected {EVENT_AGGREGATE_UPDATED}, got {}",
            msg.event_type
        ));
    }
    let event: AggregateUpdatedEvent = serde_json::from_value(msg.payload.clone())
        .map_err(|e| format!("failed to decode sentin8:stat.aggregate.updated payload: {e}"))?;
    Ok(event)
}

/// Update the app store listing metrics for the given property.
///
/// App-creates one Stat property per app instance (the instance id IS the
/// listing's property id), so an aggregate-update event for that property
/// maps 1:1 to the listing's usage metric. The aggregate value rides the
/// standard Stat ingest pipeline (`POST /v1/m/metric`, sentin8:stat:measure
/// via the service's own M2M token) - App never writes Stat tables directly.
pub fn update_listing_metrics(
    event: &AggregateUpdatedEvent,
    client: &sentin8_stat_sdk::client::Client,
) {
    let metric_name = format!("app.listing.{}", event.aggregate);
    client.metric_fire_and_forget(
        &metric_name,
        serde_json::json!({ event.aggregate.clone(): event.value }),
        Some(event.dimensions.clone()),
    );
}

/// Per-event Stat ingest bundle - the client is constructed per event with
/// the event's `property_id` (the cert-presenting transport is shared, so
/// per-event construction is cheap).
#[derive(Clone)]
pub struct StatIngest {
    /// The stat service base URL.
    pub base_url: String,
    /// The cert-presenting transport (the `app` workload
    /// certificate IS the identity - presented on the TLS handshake).
    pub http: std::sync::Arc<sentin8::middleware::http_client::Sentin8HttpClient>,
}

impl StatIngest {
    /// A client bound to the event's property (the listing's property).
    pub fn client(&self, property_id: Uuid) -> sentin8_stat_sdk::client::Client {
        sentin8_stat_sdk::client::Client::from_transport(
            self.base_url.clone(),
            property_id,
            (*self.http).clone(),
        )
    }
}

/// A `StatEventListener` subscribes to Bus `stat-pipeline` events via
/// Server-Sent Events. Bus pushes messages as they arrive - no HTTP
/// polling. The listener connects via `run`, processes
/// `sentin8:stat.aggregate.updated` events, and reconnects on disconnect with a 2s
/// backoff.
pub struct StatEventListener {
    bus: sentin8::bus::client::BusClient,
    stat: Option<StatIngest>,
}

impl StatEventListener {
    /// Build a listener over the given Bus client. `stat` enables the
    /// listing-metrics ingest (APP-1); `None` keeps the listener ACK-only
    /// (tests, or boots where the stat token source is unavailable).
    pub fn new(bus: sentin8::bus::client::BusClient, stat: Option<StatIngest>) -> Self {
        Self { bus, stat }
    }

    /// Run the listener as a long-lived task - connect to Bus via SSE,
    /// receive pushed `sentin8:stat.aggregate.updated` events, update listing metrics,
    /// and ACK via the HTTP ack endpoint. No HTTP polling. Reconnects on
    /// disconnect with a 2s backoff. Runs until the process is shut down.
    pub async fn run(&self) {
        tracing::info!(
            stream_family = STREAM_FAMILY,
            consumer_group = CONSUMER_GROUP,
            "app: stat event listener SSE consumer starting"
        );

        loop {
            let resp = match self.bus.sse_consume(STREAM_FAMILY, CONSUMER_GROUP).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "app: sse_consume failed; retrying in 2s");
                    tokio::time::sleep(RECONNECT_DELAY).await;
                    continue;
                }
            };

            tracing::info!(stream_family = STREAM_FAMILY, "app: bus SSE connected");

            let mut buffer = String::new();
            let mut stream = resp.bytes_stream();

            let mut stream_error = false;
            while let Some(chunk_result) = stream.next().await {
                let chunk = match chunk_result {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(error = %e, "app: bus SSE stream error");
                        stream_error = true;
                        break;
                    }
                };
                buffer.push_str(&String::from_utf8_lossy(&chunk));

                // Process complete events (separated by \n\n)
                while let Some(pos) = buffer.find("\n\n") {
                    let event_text = buffer[..pos].to_string();
                    buffer = buffer[pos + 2..].to_string();

                    let mut data_line = String::new();
                    for line in event_text.lines() {
                        if let Some(d) = line.strip_prefix("data: ") {
                            data_line = d.to_string();
                        }
                        // `id:` lines and `:` comments (heartbeats) are skipped -
                        // ACKs use message_id from the JSON data.
                    }

                    if data_line.is_empty() {
                        continue;
                    }

                    let msg: serde_json::Value = match serde_json::from_str(&data_line) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                    let message_id = msg["message_id"].as_str().unwrap_or("").to_string();
                    let event_type = msg["event_type"].as_str().unwrap_or("").to_string();
                    let payload = msg["payload"].clone();

                    // Reconstruct a Message to reuse parse_aggregate_updated.
                    let dummy_msg = Message {
                        message_id: String::new(),
                        stream_family: STREAM_FAMILY.into(),
                        org_id: String::new(),
                        env_id: String::new(),
                        event_type: event_type.clone(),
                        schema_version: "1.0".into(),
                        payload,
                        correlation_id: String::new(),
                        produced_by: String::new(),
                        produced_at: chrono::Utc::now().to_rfc3339(),
                        idempotency_key: None,
                        publisher_id_token: None,
                        publisher_subject: None,
                        publisher_vertical: None,
                    };

                    if let Ok(event) = parse_aggregate_updated(&dummy_msg) {
                        if let Some(stat) = &self.stat {
                            update_listing_metrics(&event, &stat.client(event.property_id));
                        } else {
                            tracing::debug!(
                                property_id = %event.property_id,
                                "app: stat ingest not configured - aggregate event dropped"
                            );
                        }
                    }

                    // ACK via HTTP to advance the consumer cursor.
                    let _ = self
                        .bus
                        .ack(STREAM_FAMILY, CONSUMER_GROUP, &message_id)
                        .await;
                }
            }

            if !stream_error {
                tracing::info!(
                    stream_family = STREAM_FAMILY,
                    "app: bus SSE stream ended; reconnecting in 2s"
                );
            }
            tokio::time::sleep(RECONNECT_DELAY).await;
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_message(event_type: &str, payload: serde_json::Value) -> Message {
        Message {
            message_id: Uuid::new_v4().to_string(),
            stream_family: STREAM_FAMILY.into(),
            org_id: Uuid::new_v4().to_string(),
            env_id: Uuid::new_v4().to_string(),
            event_type: event_type.into(),
            schema_version: "1.0".into(),
            payload,
            correlation_id: "corr-1".into(),
            produced_by: "sentin8:stat".into(),
            produced_at: Utc::now().to_rfc3339(),
            idempotency_key: None,
            publisher_id_token: None,
            publisher_subject: None,
            publisher_vertical: None,
        }
    }

    #[test]
    fn parse_aggregate_updated_succeeds() {
        let property_id = Uuid::new_v4();
        let msg = make_message(
            EVENT_AGGREGATE_UPDATED,
            serde_json::json!({
                "property_id": property_id,
                "aggregate": "pageviews",
                "window": "daily",
                "bucket_start": "2026-07-18T00:00:00Z",
                "value": 1234.5,
                "dimensions": { "path": "/home" }
            }),
        );
        let event = parse_aggregate_updated(&msg).unwrap();
        assert_eq!(event.property_id, property_id);
        assert_eq!(event.aggregate, "pageviews");
        assert_eq!(event.window, "daily");
        assert_eq!(event.value, 1234.5);
    }

    #[test]
    fn parse_aggregate_updated_rejects_wrong_event_type() {
        let msg = make_message("other.event", serde_json::json!({}));
        assert!(parse_aggregate_updated(&msg).is_err());
    }

    #[test]
    fn parse_aggregate_updated_rejects_malformed_payload() {
        let msg = make_message(EVENT_AGGREGATE_UPDATED, serde_json::json!({"foo": "bar"}));
        assert!(parse_aggregate_updated(&msg).is_err());
    }

    #[test]
    fn parse_accepts_missing_dimensions() {
        let property_id = Uuid::new_v4();
        let msg = make_message(
            EVENT_AGGREGATE_UPDATED,
            serde_json::json!({
                "property_id": property_id,
                "aggregate": "events",
                "window": "hourly",
                "bucket_start": "2026-07-18T10:00:00Z",
                "value": 10.0,
            }),
        );
        let event = parse_aggregate_updated(&msg).unwrap();
        assert_eq!(event.aggregate, "events");
        assert!(event.dimensions.is_null());
    }

    #[test]
    fn listener_constants_are_stable() {
        assert_eq!(STREAM_FAMILY, "stat-pipeline");
        assert_eq!(CONSUMER_GROUP, "app-listing-metrics");
        assert_eq!(EVENT_AGGREGATE_UPDATED, "sentin8:stat:aggregate:updated");
    }
}

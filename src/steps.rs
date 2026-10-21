// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:App
// SPDX-License-Identifier: Apache-2.0

//! Story - Flow integration for App onboarding workflows.
//!
//! App implements `POST /v1/internal/steps/execute` for App-specific step
//! types used in onboarding workflows:
//! - `KYCCheckStep` - calls a KYC provider (stub).
//! - `ApprovalReviewStep` - pauses for human approval (delegates to Flow
//! `ManualDecisionStep`).
//! - `DocumentUploadStep` - validates a document and stores it in Storage (stub).
//!
//! App registers its step handler profile with Flow via
//! `POST /v1/handlers/register` (domain=`app`).
//!
//! See and
//!

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The Flow domain App registers under.
pub const SENTIN8_APP_DOMAIN: &str = "app";

/// The internal path Flow calls back when executing an App step.
pub const INTERNAL_STEPS_PATH: &str = "/v1/internal/steps/execute";

/// App step kinds handled by `POST /v1/internal/steps/execute`.
pub const STEP_KYC_CHECK: &str = "KYCCheckStep";
/// Human-approval step (delegates to Flow `ManualDecisionStep`).
pub const STEP_APPROVAL_REVIEW: &str = "ApprovalReviewStep";
/// Document validation + Storage write (stub).
pub const STEP_DOCUMENT_UPLOAD: &str = "DocumentUploadStep";

/// A step execution request from Flow (proxy-back).
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct StepExecuteRequest {
    /// The workflow ID the step belongs to.
    pub workflow_id: String,
    /// The step name being executed.
    pub step_name: String,
    /// The step kind (one of the `STEP_*` constants).
    pub step_kind: String,
    /// The step configuration (free-form JSON).
    #[serde(default)]
    pub config: serde_json::Value,
    /// The workflow input / step input payload.
    #[serde(default)]
    pub input: serde_json::Value,
}

/// The result of executing a step.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct StepExecuteResponse {
    /// `completed` when the step finished synchronously, `paused` when it
    /// delegates to a manual decision (e.g. `ApprovalReviewStep`).
    pub status: String,
    /// Free-form output payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
    /// Error message when `status == "failed"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Execute an App step.
///
/// Dispatches by `step_kind` to the appropriate handler. Returns
/// `StepExecuteResponse` with `status = "completed"` for synchronous steps
/// and `status = "paused"` for steps that delegate to a manual decision.
pub fn execute_step(req: &StepExecuteRequest) -> Result<StepExecuteResponse, String> {
    match req.step_kind.as_str() {
        STEP_KYC_CHECK => execute_kyc_check(req),
        STEP_APPROVAL_REVIEW => execute_approval_review(req),
        STEP_DOCUMENT_UPLOAD => execute_document_upload(req),
        other => Err(format!("unknown step kind: {other}")),
    }
}

/// `KYCCheckStep` - calls a KYC provider (stub).
///
/// In production this calls an external KYC provider API. The stub returns a
/// `pass` result with the input echoed back, so workflows can be tested
/// end-to-end without a real KYC provider.
fn execute_kyc_check(req: &StepExecuteRequest) -> Result<StepExecuteResponse, String> {
    let subject = req
        .input
        .get("subject")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "KYCCheckStep requires input.subject".to_string())?;
    // TODO: call KYC provider (e.g. Onfido, Persona). Stub returns pass.
    Ok(StepExecuteResponse {
        status: "completed".into(),
        output: Some(serde_json::json!({
            "subject": subject,
            "kyc_result": "pass",
            "provider": "stub",
        })),
        error: None,
    })
}

/// `ApprovalReviewStep` - pauses for human approval.
///
/// Delegates to Flow's `ManualDecisionStep`: App returns `status = "paused"`
/// and Flow waits for a human decision (approve/reject) via
/// `POST /v1/workflows/{id}/resume`.
fn execute_approval_review(req: &StepExecuteRequest) -> Result<StepExecuteResponse, String> {
    let reviewer = req
        .config
        .get("reviewer")
        .and_then(|v| v.as_str())
        .unwrap_or("unassigned");
    Ok(StepExecuteResponse {
        status: "paused".into(),
        output: Some(serde_json::json!({
            "reason": "pending human approval",
            "reviewer": reviewer,
            "step": req.step_name,
        })),
        error: None,
    })
}

/// `DocumentUploadStep` - validate document, store in Storage (stub).
///
/// In production this validates the uploaded document (type, size, signature)
/// and stores it in Storage. The stub returns a fake Storage object ID.
fn execute_document_upload(req: &StepExecuteRequest) -> Result<StepExecuteResponse, String> {
    let doc_type = req
        .input
        .get("document_type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "DocumentUploadStep requires input.document_type".to_string())?;
    // TODO: validate document + store in Storage. Stub returns a fake object ID.
    let object_id = format!("storage-app-{}", Uuid::new_v4().simple());
    Ok(StepExecuteResponse {
        status: "completed".into(),
        output: Some(serde_json::json!({
            "document_type": doc_type,
            "sentin8_storage_object_id": object_id,
            "stored": true,
        })),
        error: None,
    })
}

/// Build the Flow handler profile registration request body for App.
///
/// App calls `POST /v1/handlers/register` on the Flow server with this body
/// to register itself as a step handler for the `app` domain.
pub fn handler_profile_payload(callback_base_url: &str, callback_token: &str) -> serde_json::Value {
    serde_json::json!({
        "domain": SENTIN8_APP_DOMAIN,
        "steps": [
            { "name": STEP_KYC_CHECK, "kind": STEP_KYC_CHECK },
            { "name": STEP_APPROVAL_REVIEW, "kind": STEP_APPROVAL_REVIEW },
            { "name": STEP_DOCUMENT_UPLOAD, "kind": STEP_DOCUMENT_UPLOAD }
        ],
        "callback_config" : {
            "base_url" : callback_base_url,
            "auth_token" : callback_token,
            "internal_path" : INTERNAL_STEPS_PATH,
        }
    })
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {

    /// Install the Graviola PQ crypto provider once - reqwest panics with
    /// "No provider set" when a client is built without one.
    fn install_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();
        });
    }
    use super::*;

    fn req(kind: &str, input: serde_json::Value) -> StepExecuteRequest {
        StepExecuteRequest {
            workflow_id: "wf-1".into(),
            step_name: format!("{kind}-1"),
            step_kind: kind.into(),
            config: serde_json::json!({}),
            input,
        }
    }

    #[test]
    fn kyc_check_passes_with_subject() {
        install_provider();
        let r = execute_step(&req(
            STEP_KYC_CHECK,
            serde_json::json!({"subject": "user-1"}),
        ))
        .unwrap();
        assert_eq!(r.status, "completed");
        let out = r.output.unwrap();
        assert_eq!(out["kyc_result"], "pass");
        assert_eq!(out["subject"], "user-1");
    }

    #[test]
    fn kyc_check_fails_without_subject() {
        install_provider();
        let r = execute_step(&req(STEP_KYC_CHECK, serde_json::json!({})));
        assert!(r.is_err());
    }

    #[test]
    fn approval_review_pauses() {
        install_provider();
        let r = req(STEP_APPROVAL_REVIEW, serde_json::json!({}));
        let mut r = r;
        r.config = serde_json::json!({"reviewer": "alice@acme"});
        let resp = execute_step(&r).unwrap();
        assert_eq!(resp.status, "paused");
        let out = resp.output.unwrap();
        assert_eq!(out["reviewer"], "alice@acme");
    }

    #[test]
    fn document_upload_stores() {
        install_provider();
        let r = execute_step(&req(
            STEP_DOCUMENT_UPLOAD,
            serde_json::json!({"document_type": "passport"}),
        ))
        .unwrap();
        assert_eq!(r.status, "completed");
        let out = r.output.unwrap();
        assert_eq!(out["document_type"], "passport");
        assert!(out["sentin8_storage_object_id"]
            .as_str()
            .unwrap()
            .starts_with("storage-app-"));
    }

    #[test]
    fn document_upload_fails_without_type() {
        install_provider();
        let r = execute_step(&req(STEP_DOCUMENT_UPLOAD, serde_json::json!({})));
        assert!(r.is_err());
    }

    #[test]
    fn unknown_step_kind_errors() {
        install_provider();
        let r = execute_step(&req("UnknownStep", serde_json::json!({})));
        assert!(r.is_err());
    }

    #[test]
    fn handler_profile_payload_includes_all_steps() {
        install_provider();
        let body = handler_profile_payload("https://sentin8-app.ops.sys.local.sentin8.dev", "tok-1");
        assert_eq!(body["domain"], SENTIN8_APP_DOMAIN);
        let steps = body["steps"].as_array().unwrap();
        assert_eq!(steps.len(), 3);
        assert_eq!(steps[0]["kind"], STEP_KYC_CHECK);
        assert_eq!(steps[1]["kind"], STEP_APPROVAL_REVIEW);
        assert_eq!(steps[2]["kind"], STEP_DOCUMENT_UPLOAD);
        assert_eq!(
            body["callback_config"]["internal_path"],
            INTERNAL_STEPS_PATH
        );
        assert_eq!(
            body["callback_config"]["base_url"],
            "https://sentin8-app.ops.sys.local.sentin8.dev"
        );
    }

    #[test]
    fn step_kind_constants_are_stable() {
        install_provider();
        assert_eq!(STEP_KYC_CHECK, "KYCCheckStep");
        assert_eq!(STEP_APPROVAL_REVIEW, "ApprovalReviewStep");
        assert_eq!(STEP_DOCUMENT_UPLOAD, "DocumentUploadStep");
    }
}

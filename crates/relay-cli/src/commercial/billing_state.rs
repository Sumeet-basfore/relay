//! Production billing lifecycle state machine and event processing.
//!
//! State Transitions:
//! NONE -> CHECKOUT -> ACTIVE -> PAST_DUE -> GRACE -> CANCELLED / EXPIRED
//!
//! Enforces:
//! 1. Server-authoritative state progression based solely on verified provider events.
//! 2. Strict event idempotency via unique event IDs.
//! 3. Out-of-order event rejection using monotonically increasing event timestamps.
//! 4. Unconditional preservation of local customer data during cancellation or refunds.

use std::collections::HashSet;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SubscriptionState {
    None,
    Checkout,
    Active,
    PastDue,
    Grace,
    Cancelled,
    Expired,
}

#[derive(Debug, Error)]
pub enum BillingStateError {
    #[error("Event {event_id} already processed (idempotent ignore)")]
    DuplicateEvent { event_id: String },
    #[error("Out-of-order event: incoming timestamp {incoming_ts} older than current state timestamp {current_ts}")]
    OutOfOrderEvent { incoming_ts: i64, current_ts: i64 },
    #[error("Invalid state transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: SubscriptionState,
        to: SubscriptionState,
    },
}

#[derive(Debug, Clone)]
pub struct SubscriptionAccount {
    pub customer_id: String,
    pub subscription_id: Option<String>,
    pub state: SubscriptionState,
    pub plan_tier: String,
    pub seat_count: u32,
    pub last_event_timestamp: i64,
    pub grace_period_end: Option<i64>,
}

impl SubscriptionAccount {
    pub fn new(customer_id: impl Into<String>) -> Self {
        Self {
            customer_id: customer_id.into(),
            subscription_id: None,
            state: SubscriptionState::None,
            plan_tier: "community".to_string(),
            seat_count: 1,
            last_event_timestamp: 0,
            grace_period_end: None,
        }
    }
}

pub struct BillingStateManager {
    processed_event_ids: HashSet<String>,
}

impl Default for BillingStateManager {
    fn default() -> Self {
        Self::new()
    }
}

impl BillingStateManager {
    pub fn new() -> Self {
        Self {
            processed_event_ids: HashSet::new(),
        }
    }

    /// Processes a verified Stripe lifecycle event and transitions the account state.
    pub fn process_event(
        &mut self,
        account: &mut SubscriptionAccount,
        event_id: &str,
        event_type: &str,
        event_timestamp: i64,
        payload_data: &serde_json::Value,
    ) -> Result<SubscriptionState, BillingStateError> {
        // 1. Idempotency check
        if self.processed_event_ids.contains(event_id) {
            return Err(BillingStateError::DuplicateEvent {
                event_id: event_id.to_string(),
            });
        }

        // 2. Out-of-order sequencing check
        if event_timestamp < account.last_event_timestamp {
            return Err(BillingStateError::OutOfOrderEvent {
                incoming_ts: event_timestamp,
                current_ts: account.last_event_timestamp,
            });
        }

        // 3. State transition execution
        let previous_state = account.state;
        let new_state = match event_type {
            "checkout.session.initiated" => match previous_state {
                SubscriptionState::None
                | SubscriptionState::Cancelled
                | SubscriptionState::Expired => SubscriptionState::Checkout,
                _ => previous_state,
            },
            "checkout.session.completed" => {
                if let Some(sub_id) = payload_data.get("subscription").and_then(|v| v.as_str()) {
                    account.subscription_id = Some(sub_id.to_string());
                }
                if let Some(seats) = payload_data.get("seats").and_then(|v| v.as_u64()) {
                    account.seat_count = seats as u32;
                }
                if let Some(tier) = payload_data.get("tier").and_then(|v| v.as_str()) {
                    account.plan_tier = tier.to_string();
                }
                account.grace_period_end = None;
                SubscriptionState::Active
            }
            "invoice.payment_failed" => {
                // Past due immediately triggers grace period (7 days = 604,800s)
                account.grace_period_end = Some(event_timestamp + 604_800);
                match previous_state {
                    SubscriptionState::Active => SubscriptionState::PastDue,
                    SubscriptionState::PastDue => SubscriptionState::Grace,
                    other => other,
                }
            }
            "invoice.payment_succeeded" => {
                // Payment recovered during PastDue or Grace reactivates to Active
                account.grace_period_end = None;
                SubscriptionState::Active
            }
            "customer.subscription.deleted" | "charge.refunded" => {
                account.grace_period_end = None;
                SubscriptionState::Cancelled
            }
            "subscription.expired" => {
                account.grace_period_end = None;
                SubscriptionState::Expired
            }
            _ => previous_state, // Unhandled events preserve current state
        };

        account.state = new_state;
        account.last_event_timestamp = event_timestamp;
        self.processed_event_ids.insert(event_id.to_string());

        Ok(new_state)
    }

    /// Evaluates whether an account currently in Grace period has expired.
    pub fn evaluate_time_boundaries(
        account: &mut SubscriptionAccount,
        now_unix: i64,
    ) -> SubscriptionState {
        if account.state == SubscriptionState::Grace || account.state == SubscriptionState::PastDue
        {
            if let Some(grace_end) = account.grace_period_end {
                if now_unix > grace_end {
                    account.state = SubscriptionState::Expired;
                    account.grace_period_end = None;
                }
            }
        }
        account.state
    }
}

-- Drop legacy tx_sender cancel/activate helper tables

-- Drop the legacy tables themselves
DROP TABLE IF EXISTS tx_sender_cancel_try_to_send_txids;
DROP TABLE IF EXISTS tx_sender_cancel_try_to_send_outpoints;
DROP TABLE IF EXISTS tx_sender_activate_try_to_send_outpoints;


#!/bin/bash
# Exit the script if any command fails
set -e

# --- Write Secrets from ENV variables to files ---
# Check if the variables are set, then write the key content to the specified file path
if [ -n "$CLIENT_CERT_KEY" ] && [ -n "$CLIENT_KEY_PATH" ]; then
  echo "Writing client key to $CLIENT_KEY_PATH..."
  # Create the directory if it doesn't exist
  mkdir -p "$(dirname "$CLIENT_KEY_PATH")"
  printf "%s" "$CLIENT_CERT_KEY" | base64 -d > "$CLIENT_KEY_PATH"
  # Set secure permissions for the key file
  chmod 600 "$CLIENT_KEY_PATH"
fi

if [ -n "$SERVER_CERT_KEY" ] && [ -n "$SERVER_KEY_PATH" ]; then
  echo "Writing server key to $SERVER_KEY_PATH..."
  # Create the directory if it doesn't exist
  mkdir -p "$(dirname "$SERVER_KEY_PATH")"
  printf "%s" "$SERVER_CERT_KEY" | base64 -d > "$SERVER_KEY_PATH"
  # Set secure permissions for the key file
  chmod 600 "$SERVER_KEY_PATH"
fi

# --- Start Application and Monitor ---
"$DOCKER_APP_PATH/$CLEMENTINE_CORE_PATH" $PARAM &
child=$!

sleep 60 &
timer_pid=$!

shutdown() {
  echo "Signal caught, shutting down all processes..."
  # Check if the process exists before trying to kill it
  if kill -0 $timer_pid 2>/dev/null; then kill $timer_pid; fi
  if kill -0 $child 2>/dev/null; then kill $child; fi
}
trap shutdown TERM INT

echo "Service (PID $child) is running. Monitoring for the first 60 seconds..."

# Wait for the first of the two processes (the app or the timer) to exit
wait -n $child $timer_pid
exit_code=$?

# Check if the timer is still running. If it is, the app must have exited first.
if kill -0 $timer_pid 2>/dev/null; then
  echo "Application exited prematurely with status $exit_code."
  echo "Keeping container alive for the remainder of the 60s to collect logs."

  # Now, wait for the timer to finish
  wait $timer_pid

  echo "60-second log collection window has passed. Exiting."
  exit $exit_code
else
  # If the timer is not running, it means it finished first.
  echo "Service has run successfully for 60 seconds. Continuing to run normally."

  # Now, just wait for the main application to finish, whenever that may be.
  wait $child
  exit_code=$?
  echo "Service has exited with status $exit_code."
  exit $exit_code
fi
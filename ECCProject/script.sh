# Specify the Flask server URL (replace 'your_public_ip' with your public IP address)
$flaskServerUrl = "http://192.168.1.4:5000"

# Define the message to send
$messageToSend = "Hello from Akash! This message is sent from a different network."

# Define the JSON payload
$jsonPayload = @{
    message = $messageToSend
} | ConvertTo-Json

# Define the endpoint URL to send the message to device A
$endpointUrlDeviceA = "$flaskServerUrl/deviceA/send_message"

# Send the message to device A
$responseDeviceA = Invoke-RestMethod -Uri $endpointUrlDeviceA -Method Post -Body $jsonPayload -ContentType "application/json"

# Display the response from device A
$responseDeviceA.response
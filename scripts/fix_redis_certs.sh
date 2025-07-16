#!/bin/bash
# Fix certificates in Redis by adding cert_name field

echo "Fixing certificate names in Redis..."

# Get all certificate keys
cert_keys=$(docker exec mcp-http-proxy-redis-1 redis-cli KEYS "cert:*")

fixed_count=0
for key in $cert_keys; do
    # Extract cert_name from key
    cert_name=${key#cert:}
    
    echo "Processing certificate: $cert_name"
    
    # Get the current certificate data
    cert_data=$(docker exec mcp-http-proxy-redis-1 redis-cli GET "$key")
    
    # Check if cert_name is missing (by looking for the field in JSON)
    if ! echo "$cert_data" | grep -q '"cert_name"'; then
        echo "  Adding cert_name to $cert_name"
        
        # Add cert_name field at the beginning of the JSON
        updated_cert_data=$(echo "$cert_data" | sed "s/{/{\"cert_name\":\"$cert_name\",/")
        
        # Update in Redis
        docker exec mcp-http-proxy-redis-1 redis-cli SET "$key" "$updated_cert_data" > /dev/null
        ((fixed_count++))
    else
        echo "  Certificate already has cert_name: $cert_name"
    fi
done

echo ""
echo "Fixed $fixed_count certificates"
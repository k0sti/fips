#!/bin/bash
# Generate FIPS node configuration files from template and topology definition.
#
# Usage: ./generate-configs.sh [mesh|chain|all]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$SCRIPT_DIR/../configs"
GENERATED_DIR="$SCRIPT_DIR/../generated-configs"
TEMPLATE_FILE="$CONFIG_DIR/node.template.yaml"

# Node data lookup functions
get_nsec() {
    case "$1" in
        a) echo "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" ;;
        b) echo "b102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fb0" ;;
        c) echo "c102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fc0" ;;
        d) echo "d102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fd0" ;;
        e) echo "e102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fe0" ;;
    esac
}

get_npub() {
    case "$1" in
        a) echo "npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m" ;;
        b) echo "npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le" ;;
        c) echo "npub1cld9yay0u24davpu6c35l4vldrhzvaq66pcqtg9a0j2cnjrn9rtsxx2pe6" ;;
        d) echo "npub1n9lpnv0592cc2ps6nm0ca3qls642vx7yjsv35rkxqzj2vgds52sqgpverl" ;;
        e) echo "npub1wf8akf8lu2zdkjkmwhl75pqvven654mpv4sz2x2tprl5265mgrzq8nhak4" ;;
    esac
}

get_docker_ip() {
    case "$1" in
        a) echo "172.20.0.10" ;;
        b) echo "172.20.0.11" ;;
        c) echo "172.20.0.12" ;;
        d) echo "172.20.0.13" ;;
        e) echo "172.20.0.14" ;;
    esac
}

get_mesh_peers() {
    case "$1" in
        a) echo "d e" ;;
        b) echo "c" ;;
        c) echo "b d e" ;;
        d) echo "a c e" ;;
        e) echo "a c d" ;;
    esac
}

get_chain_peers() {
    case "$1" in
        a) echo "b" ;;
        b) echo "a c" ;;
        c) echo "b d" ;;
        d) echo "c e" ;;
        e) echo "d" ;;
    esac
}

generate_peer_block() {
    local peer_id="$1"
    cat <<EOF
  - npub: "$(get_npub "$peer_id")"
    alias: "node-$peer_id"
    addresses:
      - transport: udp
        addr: "$(get_docker_ip "$peer_id"):4000"
    connect_policy: auto_connect
EOF
}

generate_config() {
    local node_id="$1"
    local topology="$2"
    local peers="$3"
    
    local node_name=$(echo "$node_id" | tr '[:lower:]' '[:upper:]')
    local template
    template=$(cat "$TEMPLATE_FILE")
    
    # Generate peers section
    local peers_config=""
    if [ -n "$peers" ]; then
        for peer_id in $peers; do
            if [ -n "$peers_config" ]; then
                peers_config="$peers_config"$'\n'
            fi
            peers_config="$peers_config$(generate_peer_block "$peer_id")"
        done
    else
        peers_config="  []"
    fi
    
    # Replace template variables
    local config="$template"
    config="${config//\{\{NODE_NAME\}\}/$node_name}"
    config="${config//\{\{TOPOLOGY\}\}/$topology}"
    config="${config//\{\{NPUB\}\}/$(get_npub "$node_id")}"
    config="${config//\{\{NSEC\}\}/$(get_nsec "$node_id")}"
    config="${config//\{\{PEERS\}\}/$peers_config}"
    
    echo "$config"
}

generate_topology() {
    local topology="$1"
    local output_dir="$GENERATED_DIR/$topology"
    
    echo "Generating $topology topology configs..."
    mkdir -p "$output_dir"
    
    for node_id in a b c d e; do
        local peers
        if [ "$topology" = "mesh" ]; then
            peers=$(get_mesh_peers "$node_id")
        else
            peers=$(get_chain_peers "$node_id")
        fi
        
        local output_file="$output_dir/node-$node_id.yaml"
        generate_config "$node_id" "$topology" "$peers" > "$output_file"
        echo "  ✓ Generated $output_file"
    done
}

main() {
    local requested="${1:-all}"
    
    case "$requested" in
        mesh)
            generate_topology "mesh"
            ;;
        chain)
            generate_topology "chain"
            ;;
        all)
            generate_topology "mesh"
            generate_topology "chain"
            ;;
        *)
            echo "Error: Unknown topology '$requested'"
            echo "Usage: $0 [mesh|chain|all]"
            exit 1
            ;;
    esac
    
    echo ""
    echo "✓ All configurations generated successfully!"
}

main "$@"
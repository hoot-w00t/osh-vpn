#include "node.h"
#include "logger.h"

// Returns true if packet was processed without an error
// Returns false if node should be disconnected
bool oshd_process_packet(node_t *node, void *packet)
{
    oshpacket_hdr_t *hdr = OSHPACKET_HDR(packet);
    uint8_t *payload = OSHPACKET_PAYLOAD(packet);
    const oshpacket_t *def;

    // If we have a recv_cipher, the private header and payload are encrypted,
    // so we need to decrypt it before we can process the data
    if (node->recv_cipher) {
        const size_t encrypted_size = OSHPACKET_PRIVATE_HDR_SIZE + hdr->payload_size;
        size_t decrypted_size;

        logger_debug(DBG_ENCRYPTION, "%s: Decrypting packet of %zu bytes",
            node->addrw, encrypted_size);

        // We decrypt the packet at the same location because we are using a
        // streaming cipher
        if (!cipher_decrypt(node->recv_cipher,
                OSHPACKET_PRIVATE_HDR(packet), &decrypted_size,
                OSHPACKET_PRIVATE_HDR(packet), encrypted_size,
                hdr->tag))
        {
            logger(LOG_ERR, "%s: Failed to decrypt packet", node->addrw);
            return false;
        }

        if (decrypted_size != encrypted_size) {
            logger(LOG_ERR, "%s: Decrypted packet has a different size (encrypted: %zu, decrypted: %zu)",
                node->addrw, encrypted_size, decrypted_size);
            return false;
        }
    }

    def = oshpacket_lookup(hdr->type);

    // If oshpacket_lookup returns NULL the packet type is unknown
    if (!def) {
        logger(LOG_ERR, "%s: Unknown packet type 0x%02X", node->addrw, hdr->type);
        return false;
    }

    // Verify that the payload size is valid
    if (!oshpacket_payload_size_valid(def, hdr->payload_size)) {
        logger(LOG_ERR, "%s: Invalid %s size (%u bytes)",
            node->addrw, def->name, hdr->payload_size);
        return false;
    }

    // If the node is unauthenticated we handle all the packets for ourselves,
    // nothing will be forwarded
    if (!node->authenticated)
        return def->handler_unauth(node, hdr, payload);

    node_id_t *src = node_id_find(hdr->src_node);

    // If the source node doesn't exist the remote node sent us invalid data,
    // we drop the connection
    if (!src) {
        logger(LOG_ERR, "%s: %s: Unknown source node", node->addrw, node->id->name);
        return false;
    }

    // If the source node is our local node, ignore the packet (it is likely a
    // broadcast looping back, but it could also be a routing error)
    if (src->local_node) {
        if (hdr->flags.s.broadcast) {
            logger_debug(DBG_SOCKETS,
                "%s: %s: Ignoring %s broadcast %" PRI_BRD_ID " looping back ",
                node->addrw, node->id->name, def->name, hdr->dest.broadcast.id);
        } else {
            logger(LOG_WARN, "%s: %s: Ignoring %s packet looping back",
                node->addrw, node->id->name, def->name);
        }
        return true;
    }

    if (hdr->flags.s.broadcast) {
        // If the packet is a broadcast we will check if we have seen it
        // before and drop it if that's the case
        if (node_has_seen_brd_id(src, hdr->dest.broadcast.id)) {
            logger_debug(DBG_SOCKETS,
                "%s: %s: Ignoring duplicated %s broadcast %" PRI_BRD_ID " from %s",
                node->addrw, node->id->name, def->name, hdr->dest.broadcast.id,
                src->name);
            return true;
        }

        // This is the first time we see this packet, before processing it we
        // will re-broadcast it
        node_queue_packet_broadcast_forward(node, hdr, payload, hdr->payload_size);
    } else {
        // If this packet is a unicast, we will check its destination

        const node_id_t *dest = node_id_find(hdr->dest.unicast.dest_node);

        if (!dest) {
            logger(LOG_ERR, "%s: %s: Unknown destination node", node->addrw, node->id->name);
            return false;
        }

        // If the destination node is not the local node we'll forward this packet
        if (!dest->local_node) {
            if (!def->can_be_forwarded) {
                logger(LOG_WARN,
                    "Dropping %s packet from %s to %s: This type of packet cannot be forwarded",
                    def->name, src->name, dest->name);
                return true;
            }

            if (dest->next_hop) {
                logger_debug(DBG_ROUTING, "Forwarding %s packet from %s to %s through %s",
                    def->name, src->name, dest->name, dest->next_hop->id->name);
                node_queue_packet_forward(dest->next_hop, hdr, payload, hdr->payload_size);
            } else {
                logger(LOG_INFO, "Dropping %s packet from %s to %s: No route",
                    def->name, src->name, dest->name);
            }
            return true;
        }
    }

    // If this packet was forwarded but shouldn't have been, drop it
    if (!def->can_be_forwarded && src->node_socket != node) {
        logger(LOG_ERR, "%s: %s: Rejecting forwarded %s packet (from %s)",
            node->addrw, node->id->name, def->name, src->name);
        return false;
    }

    // Otherwise the packet is for us
    return def->handler(node, src, hdr, payload);
}

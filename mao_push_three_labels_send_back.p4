#include <core.p4>
#include <v1model.p4>


struct unused_ingress_metadata_t {
    bit<1> no_op;
}

struct mao_unused_metadata {
    unused_ingress_metadata_t ingress_metadata;
}


header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header Mao_MPLS {
    bit<20> label;
    bit<3> exp;
    bit<1> bos;
    bit<8> ttl;
}

header ipv4 {
    bit<4> version;
    bit<4> ihl;
    bit<8> diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

struct Mao_MPLS_Headers {

    ethernet_t ethernet;

    Mao_MPLS[10] maoMpls;

    ipv4 ip;
}

parser ParserImpl(packet_in packet, out Mao_MPLS_Headers hdr, inout mao_unused_metadata meta, inout standard_metadata_t standard_metadata) {

    state parse_ethernet {

        packet.extract(hdr.ethernet);

        transition select(hdr.ethernet.etherType) {
            16w0x0800: parse_ipv4_tt;
        }
    }

    state parse_mpls {

        packet.extract(hdr.maoMpls.next);

        transition select(hdr.maoMpls.last.bos) {
            1w0: parse_mpls;
            1w1: accept;
        }
    }

    state parse_ipv4_tt {
        packet.extract(hdr.ip);
        transition accept;
    }

    state start {
        transition parse_ethernet;
    }
}



control verifyChecksum(in Mao_MPLS_Headers hdr, inout mao_unused_metadata meta) {

    apply {    }
}


control ingress(inout Mao_MPLS_Headers hdr, inout mao_unused_metadata meta, inout standard_metadata_t standard_metadata) {


    action drop() {
        mark_to_drop();
    }


    action push_mpls_label(bit<20> label, bit<3> exp, bit<1> bos, bit<8> ttl) {

        hdr.ethernet.etherType = 16w0x8847;

        hdr.maoMpls.push_front(1);

        hdr.maoMpls[0].label = label;
        hdr.maoMpls[0].exp = exp;
        hdr.maoMpls[0].bos = bos;
        hdr.maoMpls[0].ttl = ttl;
    }

    action push_3_labels_and_send_back(bit<20> L_1, bit<20> L_2, bit<20> L_3) {

        push_mpls_label(L_3, 3w0b001, 1w1, 8w64);
        push_mpls_label(L_2, 3w0b010, 1w0, 8w64);
        push_mpls_label(L_1, 3w0b100, 1w0, 8w64);

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }


    table ip_map_mpls {
    
        actions = {
            drop();
            push_3_labels_and_send_back;
        }
    
        key = {
            hdr.ip.dstAddr : exact;
        }
    
        size = 256;
        default_action = drop();
    }


    apply {

        if(hdr.ethernet.isValid() && hdr.ip.isValid()) {

            ip_map_mpls.apply();

        } else {
            drop();
        }
    }
}




control egress(inout Mao_MPLS_Headers hdr, inout mao_unused_metadata meta, inout standard_metadata_t standard_metadata) {

    apply {    }
}

control computeChecksum(inout Mao_MPLS_Headers hdr, inout mao_unused_metadata meta) {

    apply {    }
}


control DeparserImpl(packet_out packet, in Mao_MPLS_Headers hdr) {

    apply {

        packet.emit(hdr.ethernet);

        packet.emit(hdr.maoMpls);

        packet.emit(hdr.ip);
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;
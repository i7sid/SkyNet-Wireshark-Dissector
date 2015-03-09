/* packet-skynet.c
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "config.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>



#include <glib.h>

#include <epan/packet.h>

#define PROTO_TAG_SKYNET	"skynet"
#define PREAMBLE 12297829382473034410ULL
#define SYNC_WORD 0x2dd4

/* Wireshark ID of the it protocol */
static int proto_skynet = -1;



/* These are the handles of our subdissectors */

static dissector_handle_t skynet_handle;
static void dissect_skynet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);




/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_skynet()
*/
//static int hf_skynet_pdu = -1;
/** Kts attempt at defining the protocol */
static gint hf_skynet_payload = -1;
static gint hf_skynet_length = -1;
static gint hf_skynet_preamble = -1;
static gint hf_skynet_sync = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_skynet = -1;
static gint ett_skynet_humidity = -1;
static gint ett_skynet_checksum = -1;
static gint ett_skynet_type = -1;
static gint ett_skynet_text = -1;








static void
dissect_skynet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

    proto_item *skynet_item = NULL;
    proto_tree *skynet_tree = NULL;
//    proto_tree *skynet_header_tree = NULL;
    guint32 payload_length = 0;
    guint length = tvb_captured_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_SKYNET);
    col_clear(pinfo->cinfo,COL_INFO);
    if(length < 10) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Received not enough data for this protocol.");
    } else {
        payload_length = tvb_get_ntohs(tvb,10);
        col_add_fstr(pinfo->cinfo, COL_INFO, "payload length: %d, %s preamble, %s syncword",payload_length,tvb_get_ntoh64(tvb,0) == PREAMBLE?"correct":"false",
                 tvb_get_ntohs(tvb,8) == SYNC_WORD?"correct":"false");
    }
    if (tree) { /* we are being asked for details */
        skynet_item = proto_tree_add_item(tree, proto_skynet, tvb, 0, -1, FALSE);
        skynet_tree = proto_item_add_subtree(skynet_item, ett_skynet);
        //Preamble
        if(length>8)
            proto_tree_add_item(skynet_tree,hf_skynet_preamble,tvb,0,8,FALSE);
        //SYNC Word
        if(length>10)
        proto_tree_add_item(skynet_tree,hf_skynet_sync,tvb,8,2,FALSE);
        //Length
        if(length>12) {
            proto_tree_add_item(skynet_tree, hf_skynet_length, tvb, 10, 2, FALSE);
            //Payload
            if(payload_length+ 12 > length)
                payload_length = tvb_captured_length_remaining(tvb,12);
            proto_tree_add_item(skynet_tree,hf_skynet_payload,tvb,12,payload_length,ENC_ASCII);
        }
    }
}

static gboolean
dissect_skynet_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    (void) data;
    if(tvb_captured_length(tvb)> 10) {
        dissect_skynet(tvb,pinfo,tree);
        return (TRUE);
    }
    return FALSE;
}

void proto_register_skynet (void)
{
    /* A header field is something you can search/filter on.
    *
    * We create a structure to register our fields. It consists of an
    * array of hf_register_info structures, each of which are of the format
    * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
    */
    static hf_register_info hf[] = {
        { &hf_skynet_length,
          { "Payload length", "skynet.pl_length", FT_UINT8, BASE_DEC, NULL, 0x0,
            "length of the payload", HFILL }},

        { &hf_skynet_payload,
          { "Payload", "skynet.payload", FT_STRING, BASE_NONE, NULL, 0x0,
            "Payload", HFILL }},
        { &hf_skynet_sync,
          { "Sync", "skynet.sync", FT_UINT16, BASE_HEX, NULL, 0x0,
            "Syncword", HFILL }},
        { &hf_skynet_preamble,
          { "Preamble", "skynet.preamble", FT_UINT64, BASE_HEX, NULL, 0x0,
            "Preamble", HFILL }}
    };
    static gint *ett[] = {
        &ett_skynet,
        &ett_skynet_humidity,
        &ett_skynet_checksum,
        &ett_skynet_type,
        &ett_skynet_text
    };
    //if (proto_skynet == -1) { /* execute protocol initialization only once */
    proto_skynet = proto_register_protocol ("SKYNET Analyse", "skynet", "skynet");

    proto_register_field_array (proto_skynet, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
    register_dissector("skynet", dissect_skynet, proto_skynet);
    //}
}

void proto_reg_handoff_skynet(void)
{
    static gboolean initialized=FALSE;

    if (!initialized) {
        heur_dissector_add("sniffer",dissect_skynet_heur,proto_skynet);
        skynet_handle = create_dissector_handle(dissect_skynet, proto_skynet);
        initialized = TRUE;
        //heur_dissector_add("ip",dissect_SKYNET_heur,proto_skynet);
    }

}

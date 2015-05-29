/* packet-sniffer.c
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

#define PROTO_TAG_SNIFFER	"sniffer"


/* Wireshark ID of the it protocol */
static int proto_sniffer = -1;

static heur_dissector_list_t diss_list = NULL;


static dissector_handle_t sniffer_handle;
static void dissect_sniffer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


/* Die folgenden hf_ Variablen enthalten die IDs für die Headerfelder.
 *  Sie werden von Wireshark gesetzt, wenn die Funktion
 * proto_register_field_array aufgerufen wird.
 */

static gint hf_sniffer_rssi = -1;
static gint hf_sniffer_transmission_time = -1;

/* Das sind die IDs für die Subtrees, die wir erstellen */
static gint ett_sniffer = -1;



static void
dissect_sniffer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t *next_tvb;
    proto_item *sniffer_item = NULL;
    proto_tree *sniffer_tree = NULL;
    guint32 transmission_time;
#if VERSION_MINOR > 10
        heur_dtbl_entry_t *dtbl_etry = NULL;
#endif
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_SNIFFER);
    //col_set_str(pinfo->cinfo,COL_PACKET_LENGTH,);
    if (tree) { /* we are being asked for details */
        sniffer_item = proto_tree_add_item(tree, proto_sniffer, tvb, 0, -1, FALSE);
        sniffer_tree = proto_item_add_subtree(sniffer_item, ett_sniffer);
        //RSSI
        proto_tree_add_item(sniffer_tree,hf_sniffer_rssi,tvb,0,4,ENC_LITTLE_ENDIAN);

        transmission_time = tvb_get_letohl(tvb,4);
        proto_tree_add_uint_format(sniffer_tree,hf_sniffer_transmission_time,tvb,4,4,transmission_time,"Transmission time: %'u µs",transmission_time);
    }
    next_tvb = tvb_new_subset_remaining(tvb,8);

#if VERSION_MINOR <= 10
    dissector_try_heuristic(diss_list,next_tvb,pinfo,tree,NULL);
#else
    dissector_try_heuristic(diss_list,next_tvb,pinfo,tree,&dtbl_etry,NULL);
#endif


}

void proto_register_sniffer (void)
{
    /* A header field is something you can search/filter on.
    *
    * We create a structure to register our fields. It consists of an
    * array of hf_register_info structures, each of which are of the format
    * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
    */
    static hf_register_info hf[] = {
        { &hf_sniffer_rssi,
          { "RSSI", "sniffer.rssi", FT_FLOAT, BASE_NONE, NULL, 0x0,
            "Received Signal Strength Indicator", HFILL }},
        { &hf_sniffer_transmission_time,
          { "Transmission time", "sniffer.transmission_time", FT_UINT32,  BASE_DEC, NULL, 0x0,
            "The time between the first preamble and the last received bit", HFILL }},

    };
    static gint *ett[] = {
        &ett_sniffer
    };
    proto_sniffer = proto_register_protocol ("Sniffer Analye", "sniffer", "sniffer");

    proto_register_field_array (proto_sniffer, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
    register_dissector("sniffer", dissect_sniffer, proto_sniffer);
#if VERSION_MINOR <= 12
        if(diss_list == NULL)
            register_heur_dissector_list("sniffer",&diss_list);
#else
        if(diss_list == NULL)
            diss_list = register_heur_dissector_list("sniffer");
#endif
}

void proto_reg_handoff_sniffer(void)
{
    static gboolean initialized=FALSE;

    if (!initialized) {
        initialized = TRUE;
        sniffer_handle = create_dissector_handle(dissect_sniffer, proto_sniffer);
#if VERSION_MINOR <= 12
        if(diss_list == NULL)
            register_heur_dissector_list("sniffer",&diss_list);
#else
        if(diss_list == NULL)
            diss_list = register_heur_dissector_list("sniffer");
#endif
    }

}

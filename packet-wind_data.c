/* packet-winddata.c
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

#include "config.h"



#include <stdio.h>
#include <stdlib.h>
#include <string.h>



#include <glib.h>

#include <epan/packet.h>

#define PROTO_TAG_WINDDATA	"winddata"

/* Wireshark ID of the it protocol */
static int proto_winddata = -1;


static void dissect_winddata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Die folgenden hf_ Variablen enthalten die IDs für die Headerfelder.
 *  Sie werden von Wireshark gesetzt, wenn die Funktion
 * proto_register_field_array aufgerufen wird.
 */

static gint hf_winddata_dir = -1;
static gint hf_winddata_speed = -1;
static gint hf_winddata_id = -1;

/* Das sind die IDs für die Subtrees, die wir erstellen */
static gint ett_winddata = -1;


static void
dissect_winddata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

    proto_item *winddata_item = NULL;
    proto_tree *winddata_tree = NULL;
    guint length = tvb_captured_length(tvb);
    guint id = 0;


    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_WINDDATA);

    if(length > 8) {
        id = tvb_get_guint8(tvb,8);

    }

    col_add_fstr(pinfo->cinfo, COL_INFO, "ID: %d Speed: %d Direction: %d",id,
                 tvb_get_guint32(tvb,4,ENC_LITTLE_ENDIAN),tvb_get_guint32(tvb,0,ENC_LITTLE_ENDIAN));
    if (tree) { /* Mehr Details erforderlich */
        winddata_item = proto_tree_add_item(tree, proto_winddata, tvb, 0, -1, FALSE);
        winddata_tree = proto_item_add_subtree(winddata_item, ett_winddata);
        proto_tree_add_item(winddata_tree,hf_winddata_dir,tvb,0,4,ENC_LITTLE_ENDIAN);
        proto_tree_add_item(winddata_tree,hf_winddata_speed,tvb,4,4,ENC_LITTLE_ENDIAN);
        if(length>= 9) {
              proto_tree_add_item(winddata_tree,hf_winddata_id,tvb,8,1,FALSE);
        }
     }

}

static gboolean
dissect_winddata_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    (void) data;
    if(tvb_captured_length(tvb)>=8 && tvb_captured_length(tvb) <=9) { // Länge enthält zwischen 8 und 9 Bytes
        dissect_winddata(tvb,pinfo,tree);
        return (TRUE);
    }
    return FALSE;
}

void proto_register_winddata (void)
{
    /* Ein Header Feld wird zur Filterung oder zur Suche benutzt.
     *
     * Dafür erstellen wir ein Array mit dem die Felder registriert werden.
     * Jeder der Einträge ist von dem folgenden Format
     * { &FIELD_ID,{ FIELDNAME, FIELDABBREV, FIELDTYPE, FIELDDISPLAY,FIELDCONVERT, BITMASK,
     *  FIELDDESCR, HFILL}}.
     */

    static hf_register_info hf[] = {
        { &hf_winddata_speed,
          { "Windspeed", "winddata.speed", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Windspeed", HFILL }},
        { &hf_winddata_dir,
          { "Winddirection", "winddata.dir", FT_UINT32, BASE_DEC, NULL, 0x0,
            "Winddirection", HFILL }},
        { &hf_winddata_id,
          { "ID", "winddata.id", FT_UINT8, BASE_DEC, NULL, 0x0,
            "ID of the Sender", HFILL }}
    };
    static gint *ett[] = {
        &ett_winddata
    };
    proto_winddata = proto_register_protocol ("Wind Data Analyse", "winddata", "winddata");

    proto_register_field_array (proto_winddata, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
    register_dissector("winddata", dissect_winddata, proto_winddata);
}

void proto_reg_handoff_winddata(void)
{
    heur_dissector_add("skynet", dissect_winddata_heur, proto_winddata);// Beim Skynet Dissector als Nachfolger registrieren.
}

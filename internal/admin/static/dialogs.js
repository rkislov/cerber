// SPDX-License-Identifier: Apache-2.0
"use strict";
function openDialog(id){const dialog=document.getElementById(id);if(!dialog.open)dialog.showModal();dialog.scrollTop=0}
// Keep the original focus target only while it remains in the document. Polling
// may replace the row that opened a dialog, so fall back to stable navigation.
for(const dialog of document.querySelectorAll("dialog")){
 dialog.addEventListener("close",()=>{if(!document.querySelector("dialog[open]")&&(!document.activeElement||document.activeElement===document.body||!document.activeElement.isConnected))document.getElementById("refresh")?.focus({preventScroll:true})});
}

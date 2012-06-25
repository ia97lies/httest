var httestGenerator = function () {
  var prefManager = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch);
  return {
    init : function () {
             gBrowser.addEventListener("load", function () {
               var autoRun = prefManager.getBoolPref("extensions.httestgenerator.autorun");
               if (autoRun) {
                 httestGenerator.run();
               }
             }, false);
           },

    run : function () {
           var head = content.document.getElementsByTagName("head")[0],
           style = content.document.getElementById("httest-generator-style"),
           allLinks = content.document.getElementsByTagName("a"),
           foundLinks = 0;

           if (!style) {
             style = content.document.createElement("link");
             style.id = "httest-generator-style";
             style.type = "text/css";
             style.rel = "stylesheet";
             style.href = "chrome://httestgenerator/skin/skin.css";
             head.appendChild(style);
           }	

           for (var i=0, il=allLinks.length; i<il; i++) {
             elm = allLinks[i];
             if (elm.getAttribute("target")) {
               elm.className += ((elm.className.length > 0)? " " : "") + "httest-generator-selected";
               foundLinks++;
             }
           }
           if (foundLinks === 0) {
             alert("No links found with a target attribute");
           }
           else {
             alert("Found " + foundLinks + " links with a target attribute");
           }	
         }
  };
}();
window.addEventListener("load", httestGenerator.init, false);

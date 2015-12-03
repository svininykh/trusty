$(document).ready(function () {
 window.document.getElementById("dateXML").value = xmlStr;
 window.document.getElementById("signatureXML").value = "Signed XML.";
 window.document.getElementById("dateXMLById").value = xmlStr;
 window.document.getElementById("signatureXMLById").value = "Signed XML.";
});

if (!$.browser.msie && !navigator.javaEnabled()) {
    setMessage("messages-response", "messages-wrapper-error", "Поддержка Java в браузере не включена! Включите или <a href=\"http://java.com/ru/download/\" target=\"blank\">установите Java</a> и вновь обратитесь к этой странице.");
} else {
    insertApplet();
    blockScreen();
}

function insertApplet() {
    document.writeln('<applet width="1" height="1"');
    document.writeln(' codebase="."');
    document.writeln(' code="kz.gov.pki.knca.applet.MainApplet"');
    document.writeln(' archive="knca_applet.jar"');
    document.writeln(' type="application/x-java-applet"');
    document.writeln(' mayscript="true"');
    document.writeln(' id="KncaApplet" name="KncaApplet">');
    document.writeln('<param name="code" value="kz.gov.pki.knca.applet.MainApplet">');
    document.writeln('<param name="archive" value="knca_applet.jar">');
    document.writeln('<param name="mayscript" value="true">');
    document.writeln('<param name="scriptable" value="true">');
    document.writeln('<param name="language" value="ru">');
    document.writeln('<param name="separate_jvm" value="true">');
    document.writeln('</applet>');
}

function AppletIsReady() {
    unBlockScreen();
    $("#appstatus").text("Applet is ready!");
}

function blockScreen() {
    $.blockUI({
        message: '<img src="js/loading.gif" /><br/>Подождите, идет загрузка Java-апплета...',
        css: {
            border: 'none',
            padding: '15px',
            backgroundColor: '#000',
            '-webkit-border-radius': '10px',
            '-moz-border-radius': '10px',
            opacity: .5,
            color: '#fff'
        }
    });
}

function unBlockScreen() {
    $.unblockUI();
}
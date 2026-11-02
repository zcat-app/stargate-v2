package app.zcat.stargate.monitor;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class MonitorAlertTest {
    static MonitorAlert.Event event(List<String> failed,List<String> recovered,List<String> changed) {
        return new MonitorAlert.Event(failed,recovered,changed,0,0,0,0);
    }
    @Test void failedCheckAndRecoveryExplainTheirScopeAndNextAction() {
        var report=MonitorLedgerTest.report(MonitorLedgerTest.NOW);
        String failed=MonitorAlert.render(event(List.of("runtime_security"),List.of(),List.of()),report);
        assertTrue(failed.contains("Could not check: server software report."));
        assertTrue(failed.contains("Action: check the update-check logs on the server."));
        assertTrue(failed.contains("Browsing availability was not checked."));
        String recovery=MonitorAlert.render(event(List.of(),List.of("runtime_security"),List.of()),report);
        assertTrue(recovery.startsWith("Stargate: update checks working again\n"));
        assertTrue(recovery.contains("No action needed for these recovered checks."));
        assertTrue(recovery.contains("not browsing availability"));
    }
    @Test void releaseChangeShowsPublicVersionWithoutClaimingAnUpgradeWasInstalled() {
        var report=MonitorLedgerTest.report(MonitorLedgerTest.NOW);
        ((com.fasterxml.jackson.databind.node.ObjectNode)report.path("checks").path("tor_package_metadata").path("observation").path("packages").path("tor").path("published")).put("version","0.4.9.15-1~noble+1");
        ((com.fasterxml.jackson.databind.node.ObjectNode)report.path("checks").path("nym").path("observation")).put("latest_tag","nym-binaries-v2026.21-hanoi");
        String text=MonitorAlert.render(event(List.of(),List.of(),List.of("tor_package_metadata","nym")),report);
        assertTrue(text.contains("Nym 2026.21-hanoi, Tor 0.4.9.15-1~noble+1"));
        assertTrue(text.contains("Action: compare with installed versions before upgrading."));
        assertTrue(text.contains("Updates are not installed automatically."));
        assertTrue(text.contains("Security impact on your server needs review."));
    }
    @Test void newlySeenAndChangedNoticesAreDistinctAndNoRawReportTextLeaks() {
        var report=MonitorLedgerTest.report(MonitorLedgerTest.NOW);
        ((com.fasterxml.jackson.databind.node.ObjectNode)report.path("checks").path("nym").path("observation")).put("latest_tag","v2.0.0\nSECRET_HEADER_VALUE");
        report.put("reason","PRIVATE_DESTINATION");
        var event=new MonitorAlert.Event(List.of(),List.of(),List.of("nym","runtime_security"),2,1,3,4);
        String text=MonitorAlert.render(event,report);
        assertTrue(text.contains("Newly seen security notices: Netty 2, Quarkus 3."));
        assertTrue(text.contains("Changed security notices: Netty 1, Quarkus 4."));
        assertTrue(text.contains("Action: review all listed changes."));
        String noticesOnly=MonitorAlert.render(new MonitorAlert.Event(List.of(),List.of(),List.of(),2,1,0,0),report);
        assertTrue(noticesOnly.contains("Action: check whether these notices affect your server."));
        String reportOnly=MonitorAlert.render(event(List.of(),List.of(),List.of("runtime_security")),report);
        assertTrue(reportOnly.contains("Action: review the server software/security report."));
        assertFalse(reportOnly.contains("before upgrading"));
        assertFalse(text.contains("SECRET_HEADER_VALUE"));assertFalse(text.contains("PRIVATE_DESTINATION"));
        assertTrue(text.contains("Release information changed: Nym."));
    }
    @Test void largestCombinedEventKeepsAllEventsInsideExistingPhoneBudget() {
        var report=MonitorLedgerTest.report(MonitorLedgerTest.NOW);
        for(String name:List.of("nym","i2pd","age"))((com.fasterxml.jackson.databind.node.ObjectNode)report.path("checks").path(name).path("observation")).put("latest_tag","v"+"1".repeat(127));
        ((com.fasterxml.jackson.databind.node.ObjectNode)report.path("checks").path("quarkus").path("observation")).put("greatest_numeric_version","1".repeat(128));
        var event=new MonitorAlert.Event(List.of(),MonitorLedger.NAMES,MonitorLedger.NAMES.stream().filter(n->!n.endsWith("advisories")).toList(),500,500,500,500);
        String text=MonitorAlert.render(event,report);
        assertTrue(text.getBytes(StandardCharsets.UTF_8).length<=MonitorAlert.MAX_BYTES,text);
        assertTrue(text.contains("Release information changed: Nym, I2P, Quarkus, Java, Tor, backup tool."));
        assertTrue(text.contains("proxy package changed"));assertTrue(text.contains("software/security report changed"));
        assertTrue(text.contains("Newly seen security notices: Netty 500, Quarkus 500."));
        assertTrue(text.contains("Changed security notices: Netty 500, Quarkus 500."));
        assertTrue(text.contains("Checking works again:"));
    }
    @Test void invalidOrContradictoryEventsAreRefused() {
        assertThrows(IllegalArgumentException.class,()->event(List.of("https://private.example"),List.of(),List.of()));
        assertThrows(IllegalArgumentException.class,()->event(List.of("nym"),List.of("nym"),List.of()));
        assertThrows(IllegalArgumentException.class,()->new MonitorAlert.Event(List.of("advisories"),List.of(),List.of(),1,0,0,0));
        assertThrows(IllegalArgumentException.class,()->MonitorAlert.render(event(List.of(),List.of(),List.of()),MonitorFiles.object()));
    }
}

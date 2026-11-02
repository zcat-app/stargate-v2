// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.monitor;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Phone text only. Event detection, history and send/acknowledgement policy live elsewhere. */
final class MonitorAlert {
    // Retain the existing phone-digest size target; the sender's transport limit is larger.
    static final int MAX_BYTES = 768;
    private static final Map<String,String> LABELS = Map.ofEntries(
            Map.entry("nym","Nym"), Map.entry("i2pd","I2P"), Map.entry("quarkus","Quarkus"),
            Map.entry("temurin","Java"), Map.entry("netty","proxy package"), Map.entry("tor_package_metadata","Tor"),
            Map.entry("age","backup tool"), Map.entry("advisories","Netty security notices"),
            Map.entry("quarkus_advisories","Quarkus security notices"), Map.entry("runtime_security","server software report"));
    private static final Set<String> RELEASES = Set.of("nym","i2pd","quarkus","temurin","tor_package_metadata","age");

    record Event(List<String> failed, List<String> recovered, List<String> changed,
                 int newNetty, int changedNetty, int newQuarkus, int changedQuarkus) {
        Event {
            failed=List.copyOf(failed); recovered=List.copyOf(recovered); changed=List.copyOf(changed);
            for(var names:List.of(failed,recovered,changed))
                if(new HashSet<>(names).size()!=names.size() || !LABELS.keySet().containsAll(names))
                    throw new IllegalArgumentException("invalid alert check names");
            if(!Collections.disjoint(failed,recovered)||!Collections.disjoint(failed,changed)
                    ||changed.contains("advisories")||changed.contains("quarkus_advisories"))
                throw new IllegalArgumentException("inconsistent alert check states");
            for(int count:new int[]{newNetty,changedNetty,newQuarkus,changedQuarkus})
                if(count<0||count>1000)throw new IllegalArgumentException("invalid advisory count");
            if(newNetty+changedNetty>1000||newQuarkus+changedQuarkus>1000)
                throw new IllegalArgumentException("invalid advisory total");
            if(failed.contains("advisories")&&newNetty+changedNetty>0
                    ||failed.contains("quarkus_advisories")&&newQuarkus+changedQuarkus>0)
                throw new IllegalArgumentException("failed check cannot report known advisory counts");
        }
        boolean notices() {return newNetty+changedNetty+newQuarkus+changedQuarkus>0;}
        boolean review() {return !changed.isEmpty()||notices();}
    }

    static String render(Event event, JsonNode report) {
        String text=render(event,report,true);
        if(text.getBytes(StandardCharsets.UTF_8).length>MAX_BYTES)text=render(event,report,false);
        if(text.getBytes(StandardCharsets.UTF_8).length>MAX_BYTES)throw new IllegalArgumentException("phone alert too large");
        return text;
    }

    private static String labels(List<String> names) {
        return String.join(", ",MonitorLedger.NAMES.stream().filter(names::contains).map(LABELS::get).toList());
    }

    private static String version(JsonNode report,String name) {
        var o=report.path("checks").path(name).path("observation");
        String value=switch(name) {
            case "nym","i2pd","age" -> o.path("latest_tag").asText();
            case "quarkus" -> o.path("greatest_numeric_version").asText();
            case "temurin" -> o.path("upstream").path("release_name").asText();
            case "tor_package_metadata" -> o.path("packages").path("tor").path("published").path("version").asText();
            default -> "";
        };
        // Whitelisted public version fields only; never copy arbitrary report text.
        if(!value.matches("[A-Za-z0-9][A-Za-z0-9._+~:-]{0,127}"))return "";
        if(name.equals("nym")&&value.startsWith("nym-binaries-v"))value=value.substring(14);
        if(name.equals("temurin")&&value.startsWith("jdk-"))value=value.substring(4);
        return value;
    }

    private static String render(Event event,JsonNode report,boolean versions) {
        if(event.failed.isEmpty()&&event.recovered.isEmpty()&&!event.review())throw new IllegalArgumentException("empty alert");
        var lines=new ArrayList<String>();
        lines.add(!event.failed.isEmpty()?"Stargate: update check needs attention"
                :event.notices()||event.changed.contains("runtime_security")?"Stargate: security information changed"
                :event.review()?"Stargate: software update information changed":"Stargate: update checks working again");
        if(!event.failed.isEmpty())lines.add("Could not check: "+labels(event.failed)+".");
        if(!event.recovered.isEmpty())lines.add("Checking works again: "+labels(event.recovered)+".");
        var releaseNames=MonitorLedger.NAMES.stream().filter(event.changed::contains).filter(RELEASES::contains).toList();
        if(!releaseNames.isEmpty()) {
            var items=releaseNames.stream().map(name->{String v=versions?version(report,name):"";return LABELS.get(name)+(v.isEmpty()?"":" "+v);}).toList();
            lines.add("Release information changed: "+String.join(", ",items)+".");
        }
        if(event.changed.contains("netty"))lines.add("The selected proxy package changed.");
        if(event.changed.contains("runtime_security"))lines.add("The server software/security report changed.");
        if(event.newNetty+event.newQuarkus>0)lines.add("Newly seen security notices: "+counts(event.newNetty,event.newQuarkus)+".");
        if(event.changedNetty+event.changedQuarkus>0)lines.add("Changed security notices: "+counts(event.changedNetty,event.changedQuarkus)+".");
        if(!event.failed.isEmpty()) {
            lines.add(event.review()?"Action: check update logs and review all listed changes.":"Action: check the update-check logs on the server.");
            lines.add("Browsing availability was not checked.");
        } else if((event.notices()?1:0)+(!releaseNames.isEmpty()?1:0)
                +(event.changed.contains("runtime_security")?1:0)+(event.changed.contains("netty")?1:0)>1)
            lines.add("Action: review all listed changes.");
        else if(event.notices())lines.add("Action: check whether these notices affect your server.");
        else if(!releaseNames.isEmpty())lines.add("Action: compare with installed versions before upgrading.");
        else if(event.changed.contains("runtime_security"))lines.add("Action: review the server software/security report.");
        else if(event.review())lines.add("Action: review the selected proxy package.");
        else {lines.add("No action needed for these recovered checks.");lines.add("This reports check recovery, not browsing availability.");}
        if(event.review()){lines.add("Security impact on your server needs review.");lines.add("Updates are not installed automatically.");}
        return String.join("\n",lines)+"\n";
    }

    private static String counts(int netty,int quarkus) {
        var counts=new ArrayList<String>();if(netty>0)counts.add("Netty "+netty);if(quarkus>0)counts.add("Quarkus "+quarkus);return String.join(", ",counts);
    }
}

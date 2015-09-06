package ru.ussgroup.security.trusty;

import java.util.HashMap;
import java.util.Map;

public class SubjectDNParser {
    private Map<String, String> names = new HashMap<>();
    
    public SubjectDNParser(String name) {
        String[] values = name.split(",");
        
        names = new HashMap<>();
        
        for (String value : values) {
            names.put(value.split("=")[0].trim(), value.split("=")[1].trim());
        }
    }
    
    public String getIin() {
        return names.get("SERIALNUMBER").substring(3);
    }
    
    public String getBin() {
        return names.get("OU").substring(3);
    }
}

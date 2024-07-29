package io.security.springsecuritymaster;

import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class DataService {
    @PreFilter("filterObject.owner == authentication.name")
    public List<MethodAccountDTO> writeList(List<MethodAccountDTO> data) {
        return data;
    }
    // Map은 List와 달리, filterObject.value로 접근해야 한다.
    @PreFilter("filterObject.value.owner == authentication.name")
    public Map<String, MethodAccountDTO> writeMap(Map<String, MethodAccountDTO> data) {
        return data;
    }

    @PostFilter("filterObject.owner == authentication.name")
    public List<MethodAccountDTO> readList() {
        return new ArrayList<>(List.of(
                new MethodAccountDTO("user", false),
                new MethodAccountDTO("db", false),
                new MethodAccountDTO("admin", false)
        ));
    }

    @PostFilter("filterObject.value.owner == authentication.name")
    public Map<String, MethodAccountDTO> readMap() {
        return new HashMap<>(Map.of(
                "user", new MethodAccountDTO("user", false),
                "db", new MethodAccountDTO("db", false),
                "admin", new MethodAccountDTO("admin", false)
        ));
    }
}

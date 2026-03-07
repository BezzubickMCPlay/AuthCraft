// com/authcraft/core/model/Role.java
package com.authcraft.core.model;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class Role {

    private String name;
    private String permission;
    private String inherits;
    private List<String> commands;
    private boolean requires2fa;
    private int priority;

    public Role() {
        this.commands = new ArrayList<>();
        this.requires2fa = false;
        this.priority = 0;
    }

    public Role(String name, String permission) {
        this();
        this.name = name;
        this.permission = permission;
    }

    /**
     * Get all commands including inherited ones.
     */
    public Set<String> getEffectiveCommands(java.util.Map<String, Role> allRoles) {
        Set<String> effective = new HashSet<>(commands);
        if (inherits != null && allRoles.containsKey(inherits)) {
            effective.addAll(allRoles.get(inherits).getEffectiveCommands(allRoles));
        }
        return effective;
    }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getPermission() { return permission; }
    public void setPermission(String permission) { this.permission = permission; }

    public String getInherits() { return inherits; }
    public void setInherits(String inherits) { this.inherits = inherits; }

    public List<String> getCommands() { return commands; }
    public void setCommands(List<String> commands) { this.commands = commands; }

    public boolean isRequires2fa() { return requires2fa; }
    public void setRequires2fa(boolean requires2fa) { this.requires2fa = requires2fa; }

    public int getPriority() { return priority; }
    public void setPriority(int priority) { this.priority = priority; }
}
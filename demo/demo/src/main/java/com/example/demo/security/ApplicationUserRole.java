
package com.example.demo.security;

import com.google.common.collect.Sets;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public enum ApplicationUserRole {

  STUDENT(Sets.newHashSet()),
  ADMIN(Sets.newHashSet(ApplicationPermission.COURSE_READ,ApplicationPermission.COURSE_WRITE,ApplicationPermission.STUDENT_READ,ApplicationPermission.STUDENT_WRITE)),
  ADMINTRAINEE(Sets.newHashSet(ApplicationPermission.COURSE_READ,ApplicationPermission.STUDENT_READ));

  private final Set<ApplicationPermission> permissions;


  ApplicationUserRole(Set<ApplicationPermission> permissions) {
    this.permissions = permissions;
  }

  public Set<ApplicationPermission>getPermission(){
    return permissions;
  }

  public Set<SimpleGrantedAuthority> getGrantedAuthority(){
    Set<SimpleGrantedAuthority> permission=getPermission().stream()
        .map(s-> new SimpleGrantedAuthority(s.getPermission()))
        .collect(Collectors.toSet());

    permission.add(new SimpleGrantedAuthority("ROLE_" + this.name()));
    return permission;
  }
}

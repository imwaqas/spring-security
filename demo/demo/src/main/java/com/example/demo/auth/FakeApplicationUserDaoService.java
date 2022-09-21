package com.example.demo.auth;

import com.example.demo.security.ApplicationUserRole;
import com.google.common.collect.Lists;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao{

  private final PasswordEncoder passwordEncoder;

  public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  public Optional<ApplicationUser> selectApplicaqtionUserByUSerName(String userName) {
    return getApplicationUser()
        .stream()
        .filter(a->a.getUsername().equals(userName))
        .findFirst();
  }

  private List<ApplicationUser> getApplicationUser() {
    List<ApplicationUser> applicationUsers = Lists.newArrayList(
        new ApplicationUser(
            "Waqas",
            passwordEncoder.encode("password"),
            ApplicationUserRole.ADMIN.getGrantedAuthority(),
            true,
            true,
            true,
            true)

    );
return applicationUsers;
  }
}

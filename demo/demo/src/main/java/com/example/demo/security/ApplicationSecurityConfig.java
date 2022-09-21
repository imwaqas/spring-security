package com.example.demo.security;

import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JwtConfig;
import com.example.demo.jwt.JwtTokenVerifier;
import com.example.demo.jwt.JwtUserNameAndPasswordAuthenticationFilter;
import com.example.demo.student.Student;
import java.util.concurrent.TimeUnit;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)  //this is use to enable @PreAuthorize annotation
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter
{

  private final PasswordEncoder passwordEncoder;
  private final ApplicationUserService applicationUserService;

  private final SecretKey secretKey;
  private final JwtConfig jwtConfig;

  public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
      ApplicationUserService applicationUserService, SecretKey secretKey, JwtConfig jwtConfig) {
    this.passwordEncoder = passwordEncoder;
    this.applicationUserService = applicationUserService;
    this.secretKey = secretKey;
    this.jwtConfig = jwtConfig;
  }





  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
//        .csrf().disable()
//        .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()) //only when using browser
//        .and()
        .csrf().disable()
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .addFilter(new JwtUserNameAndPasswordAuthenticationFilter(authenticationManager(),jwtConfig,secretKey))
        .addFilterAfter(new JwtTokenVerifier(secretKey,jwtConfig), JwtUserNameAndPasswordAuthenticationFilter.class)
        .authorizeRequests()
        .antMatchers("/","index","/css/*","/js/*").permitAll()
        .antMatchers("/api/**").hasRole(ApplicationUserRole.STUDENT.name())
        // this is replace by @PreAuthorize
//        .antMatchers(HttpMethod.POST,"/management/api/**").hasAuthority(ApplicationPermission.COURSE_WRITE.getPermission())
//        .antMatchers(HttpMethod.DELETE,"/management/api/**").hasAuthority(ApplicationPermission.COURSE_WRITE.getPermission())
//        .antMatchers(HttpMethod.PUT,"/management/api/**").hasAuthority(ApplicationPermission.COURSE_WRITE.getPermission())
//        .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(),ApplicationUserRole.ADMINTRAINEE.name())
        .anyRequest()
        .authenticated();
//        .and()
//        //        .httpBasic(); //this is for basic auth
//        .formLogin()
//        .loginPage("/login").permitAll()
//        .defaultSuccessUrl("/courses",true) //to route to courses.html page after login, check TemplateController
//        .passwordParameter("password")
//        .usernameParameter("username")
//        .and()
//        .rememberMe().tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//        .key("securekey")
//        .rememberMeParameter("remember-me")
//        .and()
//        .logout()
//        .logoutUrl("/logout")
//        .logoutRequestMatcher(new AntPathRequestMatcher("/logout","GET"))
//          .clearAuthentication(true)
//          .invalidateHttpSession(true)
//          .deleteCookies("JSESSIONID","remember-me")
//          .logoutSuccessUrl("/login");
//
////        .rememberMe();//default 2 weeks


  }

//  @Override
//  @Bean
//  protected UserDetailsService userDetailsService() {
//
//    UserDetails user =User.builder()
//        .username("Waqas")
//        .password(passwordEncoder.encode("Waqas"))
////        .roles(ApplicationUserRole.STUDENT.name()) //ROLE_STUDENT
//        .authorities(ApplicationUserRole.STUDENT.getGrantedAuthority())
//        .build();
//
//    UserDetails syed=User.builder()
//        .username("Syed")
//        .password(passwordEncoder.encode("Syed"))
////        .roles(ApplicationUserRole.ADMIN.name())
//        .authorities(ApplicationUserRole.ADMIN.getGrantedAuthority())
//        .build();
//
//    UserDetails tom=User.builder()
//        .username("Tom")
//        .password(passwordEncoder.encode("Tom"))
////        .roles(ApplicationUserRole.ADMINTRAINEE.name())
//        .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthority())
//        .build();
//
//    return new InMemoryUserDetailsManager(user,syed,tom);
//  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.authenticationProvider(daoAuthenticationProvider());
  }

  @Bean
  public DaoAuthenticationProvider daoAuthenticationProvider(){
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setPasswordEncoder(passwordEncoder);
    provider.setUserDetailsService(applicationUserService);
    return provider;
  }
}

package com.ahmed.miniprojet.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf().disable()
                        .authorizeRequests()
                                .requestMatchers("/webjars/**", "/login", "/register", "/register/save").permitAll()
                        .requestMatchers("/showCreate", "/deleteAlbum","/showUpdate","/updateAlbum" ).hasAuthority("ADMIN")
                .anyRequest().authenticated().and()
                                .formLogin(form -> form
                                        .loginPage("/login")
                                        .defaultSuccessUrl("/albumsList", true)
                                        .loginProcessingUrl("/login")
                                        .failureUrl("/login?error=true")
                                        .permitAll()
                                ).logout(logout -> logout
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout")).permitAll()
                        .invalidateHttpSession(true)
                        .logoutSuccessUrl("/login?logout=true")
                ).exceptionHandling().accessDeniedPage("/accessDenied");
        return httpSecurity.build();
    }
}

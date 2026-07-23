package com.loganalytics.config;

import com.loganalytics.service.AppUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final AppUserDetailsService userDetailsService;
    private final CustomAuthenticationSuccessHandler successHandler;

    public SecurityConfig(AppUserDetailsService userDetailsService,
                          CustomAuthenticationSuccessHandler successHandler) {
        this.userDetailsService = userDetailsService;
        this.successHandler = successHandler;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {

        DaoAuthenticationProvider provider =
                new DaoAuthenticationProvider();

        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());

        return provider;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http)
            throws Exception {

        http
            .authenticationProvider(authenticationProvider())

            .csrf(csrf -> csrf.disable())

            .headers(headers -> headers
                    .frameOptions(frame -> frame.disable())
            )

            .authorizeHttpRequests(auth -> auth

                    .requestMatchers(new AntPathRequestMatcher("/")).permitAll()
                    .requestMatchers(new AntPathRequestMatcher("/login")).permitAll()
                    .requestMatchers(new AntPathRequestMatcher("/register")).permitAll()

                    .requestMatchers(new AntPathRequestMatcher("/css/**")).permitAll()
                    .requestMatchers(new AntPathRequestMatcher("/js/**")).permitAll()
                    .requestMatchers(new AntPathRequestMatcher("/images/**")).permitAll()

                    .requestMatchers(new AntPathRequestMatcher("/h2-console/**")).permitAll()

                    .requestMatchers(new AntPathRequestMatcher("/api/auth/register")).permitAll()

                    .requestMatchers(new AntPathRequestMatcher("/admin/**")).hasRole("ADMIN")

                    // FIX: admins can now open the user dashboard too ("User View" button)
                    .requestMatchers(new AntPathRequestMatcher("/user/**")).hasAnyRole("USER", "ADMIN")

                    .requestMatchers(new AntPathRequestMatcher("/api/dashboard/**")).hasRole("ADMIN")

                    .anyRequest().authenticated()
            )

            .formLogin(form -> form
                    .loginPage("/login")
                    .loginProcessingUrl("/login")
                    .successHandler(successHandler)
                    .failureUrl("/login?error=true")
                    .permitAll()
            )

            .logout(logout -> logout
                    // FIX: default Spring Security logout only matches POST /logout.
                    // Our dashboard buttons are plain <a href="/logout"> links (GET),
                    // so we explicitly allow GET here to make them work.
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                    .logoutSuccessUrl("/login?logout")
                    .invalidateHttpSession(true)
                    .clearAuthentication(true)
                    .deleteCookies("JSESSIONID")
                    .permitAll()
            );

        return http.build();
    }
}
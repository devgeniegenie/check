package com.example.userservice.security;

import com.example.userservice.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurity {

    private final UserService userService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ObjectPostProcessor<Object> objectPostProcessor;

    @Autowired
    private Environment env;

    @Bean
    protected SecurityFilterChain config(HttpSecurity http) throws Exception {
        RequestMatcher[] requestMatchersList = new RequestMatcher[]{
                new AntPathRequestMatcher("/users/**"),
                new AntPathRequestMatcher("/"),
                new AntPathRequestMatcher("/**"),
                new AntPathRequestMatcher("/actuator/**")
        };

        http.csrf().disable();
        http.headers().frameOptions().disable();
        http.authorizeHttpRequests(authorize -> {
                    try {
                        authorize
//                                .requestMatchers(new AntPathRequestMatcher("/users/**"), new AntPathRequestMatcher("/"), new AntPathRequestMatcher("/**")).permitAll()
                                .requestMatchers(requestMatchersList).permitAll()
                                .requestMatchers(new IpAddressMatcher("127.0.0.1")).permitAll()
                                .and()
                                .addFilter(getAuthenticationFilter());
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
        );
        return http.build();
    }

    public AuthenticationManager authenticationManager(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder);
        return auth.build();
    }

    private AuthenticationFilter getAuthenticationFilter() throws Exception {
        AuthenticationManagerBuilder builder = new AuthenticationManagerBuilder(objectPostProcessor);
        AuthenticationFilter authenticationFilter = new AuthenticationFilter(authenticationManager(builder), userService, env);
//        authenticationFilter.setAuthenticationManager(authenticationManager(builder));
        return authenticationFilter;
    }

}
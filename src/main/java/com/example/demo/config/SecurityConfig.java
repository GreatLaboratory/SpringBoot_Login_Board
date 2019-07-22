package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(
                        "/registration/**","/board",
                        "/js/**",
                        "/css/**",
                        "/img/**",
                        "/webjars/**")
                .permitAll()
                .anyRequest().authenticated()

                .and()
                .formLogin()
                .loginPage("/login")
                .permitAll()

                .and()
                .logout()
                .invalidateHttpSession(true)
                .clearAuthentication(true)
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .permitAll();
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // 커스텀인증을 구현하는 컴포넌트 -> 이거는 내가 직접 인증방식을 구현해야한다.
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider auth = new DaoAuthenticationProvider();

        // 인증코드구현
        // auth.setUserDetailsService(); -> 여기 파라미터에다가 userDetailService를 상속받은 내가 만든 userService 인터페이스를 넣는다.
        // 내가 만든 userService 구현클래스는 userDetailService의 추상메소드를 구현해놓은게 있어야하고 그 내용을 파라미터로 넣는게 중요.
        auth.setPasswordEncoder(passwordEncoder());

        return auth;
    }

    // 위에 있는 커스텀인증을 구현한 authenticationProvider()을 실제/진짜배기 권한매니저로 제공&빌드한다.
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
    }
}

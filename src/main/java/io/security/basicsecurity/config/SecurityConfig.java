package io.security.basicsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//    @Autowired
//    UserDetailsService userDetailsService;
//
//    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();   //요청에 대한 보안검색 시작(모든 요청에 대해서 인증을 받도록 설정 - 인가정책)

        http
                .formLogin();       //인증정책(formlogin을 통해서)

        http
                .sessionManagement()
//                .sessionFixation().none();      //무방비상태
                .sessionFixation().changeSessionId();      //sessionId를 변경하여 정보에 접근 차단
//        http
//                .sessionManagement()
//                .maximumSessions(1)       //세션의 갯수 설정(-1  =  무한대)
//                .maxSessionsPreventsLogin(true);     // 세션의 갯수를 초과했을 경우, 현재 로그인을 차단  (false일때는 이전의 로그인을 차단)

//                .loginPage("/loginPage")   //로그인 페이지 url
//                .defaultSuccessUrl("/")   //로그인 성공시 이동할 url
//                .failureUrl("/loginPage")    //로그인 실패시 이동할 url
//                .usernameParameter("userId")     //username 파라미터명 변경
//                .passwordParameter("pw")       //password 파라미터명 변경
//                .loginProcessingUrl("/login_proc")     //로그인 form action url
//                .successHandler(new AuthenticationSuccessHandler() {  //익명 class 사용 (인증 성공시 handler 작동)
//                    @Override
//                    // 인증에 성공하면 인증의 결과를 담은 객체
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        System.out.println("authentication" + authentication.getName());
//                        response.sendRedirect("/");
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() { // (인증 실패시 handler 작동)
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("exception" + exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                })
//                .permitAll();    //loginPage에 접근 하는 경우 접근을 제한하지 않음
//
//
//        http
//                .logout()
//                .logoutUrl("/logout")      //logout은 post 방식
//                .logoutSuccessUrl("/logout")
//                .addLogoutHandler(new LogoutHandler() {
//                    @Override
//                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//                        HttpSession session = request.getSession();
//                        session.invalidate();
//                    }
//                })
//                .logoutSuccessHandler(new LogoutSuccessHandler() {
//                    @Override
//                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
//                .deleteCookies("remember-me");     //cookie 삭제
//                .and()
//                .rememberMe()
//                .rememberMeParameter("remember")
//                .tokenValiditySeconds(3600)
//                .userDetailsService(userDetailsService);
    }
}

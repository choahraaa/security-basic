package io.security.basicsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
@Order(0)     //설정클래스 초기화하는 순서 (요청 순서 : 순서에 따라서 자원 접근 허용이 달라짐 / 넓은 범위의 요청 순서가 우선순위가 낮아야함)
public class SecurityConfig extends WebSecurityConfigurerAdapter {  //첫번쪠 시큐리티 설정 클래스

    protected void configure(HttpSecurity http) throws Exception {
        http
                .antMatcher("/admin/**")   //특정 url 설정
                .authorizeRequests()
                .anyRequest().authenticated()     //모든 사용자가 인증을 받아야만 자원에 접근가능 (authenticated)
                .and()
                .httpBasic();   //인증방식 - 방식에 따라서 필터의 구성이 다름
    }
}//인증방식

@Configuration
@Order(1)
class SecurityConfig2 extends WebSecurityConfigurerAdapter {  //두번쩨 시큐리티 설정 클래스

    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().permitAll()    //인증을 받지 않아도 접근 가능 (permitAll)
                .and()
                .formLogin();    //인증방식
    }

}

//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
//        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
//        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");    //각기 다른 권한의 계정 생성
//        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER");    //admin 계정이 다른 권한에 해당하는 자원의 접근을 가능하게 함
//    }

    //    @Autowired
//    UserDetailsService userDetailsService;
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .antMatchers("/login").permitAll()     //로그인 페이지 접근 권한 설정 해제
//                .antMatchers("/user").hasRole("USER")     //특정 요청에 대해서 인가정책을 매치 (권한 심사)
//                .antMatchers("/admin/pay").hasRole("ADMIN")
//                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")      // 권한 설정에 순서도 중요(전체 권한 먼저 설정후 부분 권한 설정을 하면 안됨)
//                .anyRequest().authenticated();   //요청에 대한 보안검색 시작(모든 요청에 대해서 인증을 받도록 설정 - 인가정책)
//
//        http
//                .formLogin();       //인증정책(formlogin을 통해서)
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        RequestCache requestCache = new HttpSessionRequestCache();     //세션에 저장되어있는 이전의 정보 객체
//                        SavedRequest savedRequest = requestCache.getRequest(request, response);   //세션에 저장되어있는 요청과 응답 객체
//                        String redirectUrl = savedRequest.getRedirectUrl();
//                        response.sendRedirect(redirectUrl);    //세션에 저장되어있는 redirectUrl로 리다이렉트
//                    }
//                });
//
//        http
//                .exceptionHandling()
//                .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
//                .accessDeniedHandler(new AccessDeniedHandler() {
//                    @Override
//                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
//                        response.sendRedirect("/denied");
//                    }
//                });

//        http
//                .sessionManagement()
//                .sessionFixation().none();      //무방비상태
//                .sessionFixation().changeSessionId();      //sessionId를 변경하여 정보에 접근 차단
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

package com.mycompany.webapp.security;

import javax.annotation.Resource;
import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import lombok.extern.slf4j.Slf4j;

@EnableWebSecurity
@Slf4j
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Resource
	private DataSource dataSource;
	
	@Resource
	private CustomUserDetailsService customUserDetailsService;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {	
		log.info("configure(HttpSecurity http) 실행");
		//폼 로그인 비활성화
		//로그인 폼을 제공X
		http.formLogin().disable();
		
		//사이트간 요청 위조 방지 비활성화
		http.csrf().disable();
		
		//요청 경로 권한 설정
		http.authorizeRequests()
			.antMatchers("/board/**").authenticated()
			.antMatchers("/**").permitAll();
		
		//세션 비활성화
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		
		//JwtCheckFilter 추가
		//id password를 제공하는 것이 아니라 Jwt객체를 전달하기 때문에
		//id, password로 인증을 확인하는 Filter전에 추가되어야 한다.
		JwtCheckFilter jwtCheckFilter = new JwtCheckFilter();
		http.addFilterBefore(jwtCheckFilter, UsernamePasswordAuthenticationFilter.class);
	
		//CORS 설정 교차 출처 리소스 공유 활성화
		//http.authorizeRequests().antMatchers("/api/**").authenticated();
		//http.addFilterBefore(apiCheckFilter(), UsernamePasswordAuthenticationFilter.class);
		//http.addFilterBefore(apiLoginFilter(), UsernamePasswordAuthenticationFilter.class);
		http.cors();
	}	
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		log.info("configure(AuthenticationManagerBuilder auth) 실행");
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(customUserDetailsService);
		provider.setPasswordEncoder(passwordEncoder());
		auth.authenticationProvider(provider);
	}	
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		log.info("configure(WebSecurity web) 실행");
		DefaultWebSecurityExpressionHandler defaultWebSecurityExpressionHandler = new DefaultWebSecurityExpressionHandler();
		defaultWebSecurityExpressionHandler.setRoleHierarchy(roleHierarchyImpl());	
		web.expressionHandler(defaultWebSecurityExpressionHandler);
		web.ignoring()
		.antMatchers("/images/**")
		.antMatchers("/css/**")
		.antMatchers("/js/**")
		.antMatchers("/bootstrap-4.6.0-dist/**")
		.antMatchers("/jquery/**")
		.antMatchers("/favicon.ico");		
	}	
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		//return new BCryptPasswordEncoder();
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
	
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
	
	@Bean
	public RoleHierarchyImpl roleHierarchyImpl() {
		log.info("실행");
		RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
		roleHierarchyImpl.setHierarchy("ROLE_ADMIN > ROLE_MANAGER > ROLE_USER");
		return roleHierarchyImpl;
	}
	
	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		//모든 요청 사이트 허용
		configuration.addAllowedOrigin("*");
		//모든 요청 방식 허용
		configuration.addAllowedMethod("*");
		//모든 요청 헤더 허용
		configuration.addAllowedHeader("*");
		
		//모든 URL 요청에 대해서 위 내용을 적용
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
			
}
 
 
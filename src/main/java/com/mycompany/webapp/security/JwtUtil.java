package com.mycompany.webapp.security;

import java.util.Date;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JwtUtil {
	//비밀키 (외부에 노출이 되면 안된다)
	private static final String secretKey = "12345";
	
	//JWT 생성
	//JWT안에는 중요한 정보는 될 수 있으면 저장하지 않는다
	public static String createToken(String mid, String authority) {
		log.info("실행");
		String result = null;
		try {
			//헤더 설정
			//토큰의 유효기간 설정
			//페이로드 설정
			//서명 설정 : 해당 서버에서 발행한 (secretKey로) jwt인지를 확인
			//토큰 생성
			String token = Jwts.builder()
				.setHeaderParam("alg","HS256").setHeaderParam("typ", "JWT") 
				.setExpiration(new Date(new Date().getTime() + 1000*60*60*24)) 
				.claim("mid", mid).claim("authority", authority) 
				.signWith(SignatureAlgorithm.HS256, secretKey.getBytes("UTF-8"))
				.compact();
			result = token;
		} catch(Exception e) { }
		return result;
	}
	
	//클라이언트에서 받은 JWT 토큰 유효성 검사
	//유효기간과 서명을 확인 후 토큰 안에 페이로드를 리턴
	public static Claims validateToken(String token) {
		Claims result = null;
		log.info("실행");
		try {
			result = Jwts.parser()
					.setSigningKey(secretKey.getBytes("UTF-8"))
					.parseClaimsJws(token)
					.getBody();
		}catch(Exception e) { }
		return result;
	}
	
	//JWT에서 정보 얻기
	public static String getMid(Claims claims) {
		log.info("실행");
		return claims.get("mid", String.class);
	}
	
	public static String getAuthority(Claims claims) {
		log.info("실행");
		return claims.get("authority", String.class);
	}
	
	//확인
	public static void main(String[] args) throws Exception {
		String mid = "user";
		String authority = "ROLE_USER";
		String jwt = createToken(mid, authority);
		
		log.info(jwt);
		
		//토큰 유효성 검사
		Claims claims = validateToken(jwt);
		if(claims != null) {
			log.info("유효한 토큰");
			log.info("mid: " + getMid(claims));
			log.info("authority: " + getAuthority(claims));
		} else {
			log.info("유효하지 않은 토큰");
		}
	}
}

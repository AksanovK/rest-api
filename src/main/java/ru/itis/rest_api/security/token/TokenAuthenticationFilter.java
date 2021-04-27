package ru.itis.rest_api.security.token;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.itis.rest_api.models.Token;
import ru.itis.rest_api.models.User;
import ru.itis.rest_api.repositories.TokensRepository;
import ru.itis.rest_api.repositories.UsersRepository;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.Optional;
import java.util.function.Supplier;

@Component
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    public TokensRepository tokensRepository;

    @Autowired
    public UsersRepository usersRepository;

    @Override
    public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        String token = request.getHeader("X-TOKEN");

        if (token != null) {
            try {
                DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC256("secret"))
                        .build()
                        .verify(token);
                String id = decodedJWT.getSubject();
                Date time = decodedJWT.getExpiresAt();
                Date nowTime = new Date();
                if ((nowTime.getTime() - time.getTime()) > 900000) {
                    Token refresh_token = tokensRepository.findById(Long.parseLong(id))
                            .orElseThrow((Supplier<Throwable>) () -> new UsernameNotFoundException("Token not found"));
                    Long refresh_time = refresh_token.getTime_of_creating().getTime();
                    Long now_time = new Date().getTime();
                    if ((now_time - refresh_time > 604800000)) {
                        response.sendRedirect("/login");
                    } else {
                        User user = usersRepository.findById(Long.parseLong(id))
                                .orElseThrow((Supplier<Throwable>) () -> new UsernameNotFoundException("User not found"));
                        TokensUtil tokensUtil = new TokensUtil(user);
                        System.out.println(tokensUtil.getAccessToken());
                        String new_refresh_token = tokensUtil.getRefreshToken();
                        tokensRepository.deleteByRefreshToken(refresh_token.getRefreshToken());
                        Token new_token = new Token(Long.parseLong(id), new_refresh_token, new Date());
                        tokensRepository.save(new_token);
                    }
                }
            } catch (JWTVerificationException e) {
                System.err.println(e.getMessage());
            } catch (Throwable throwable) {
                throw new UsernameNotFoundException("Token not found");
            }
        }


        if (token != null) {
            TokenAuthentication tokenAuthentication = new TokenAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(tokenAuthentication);
        }

        filterChain.doFilter(request, response);
    }

}

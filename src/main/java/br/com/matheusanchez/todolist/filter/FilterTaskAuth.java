package br.com.matheusanchez.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.matheusanchez.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        var ServletPath = request.getServletPath();
        if (ServletPath.startsWith("/tasks/")) {
            // Busca no header da requisição o Auth e salva em uma variavel.
            var authorization = request.getHeader("Authorization");

            // Remove o Basic e o espaço final da string.
            var authEncoded = authorization.substring("Basic".length()).trim();

            // Decodifica o base64 que foi gerado acima e salva em um array de bytes.
            byte[] authDecoded = Base64.getDecoder().decode(authEncoded);

            // Converte o array de bytes acima para String.
            var authString = new String(authDecoded);

            // Separa a string gerada em 2 com username e password.
            String[] credentials = authString.split(":");
            String username = credentials[0];
            String password = credentials[1];

            var user = this.userRepository.findByUsername(username);
            if (user == null) {
                response.sendError(401);
            } else {
                var verifiedPassword = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                if (verifiedPassword.verified) {
                    request.setAttribute("idUser", user.getId());
                    filterChain.doFilter(request, response);
                } else {
                    response.sendError(401);
                }
            }
        } else {
            filterChain.doFilter(request, response);
        }

    }

}

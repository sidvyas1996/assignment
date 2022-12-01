package com.emeritus.assignment.filter;


import org.springframework.stereotype.Component;

@Component
public class JwtFilter  {

    /*@Autowired
    private UserAuthenticationService authenticationService;
    @Autowired
    private JWTUtility jwtUtility;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        String authorization = httpServletRequest.getHeader("Authorization");
        String token = null;
        String userName = null;

        if(null != authorization && authorization.startsWith("Bearer ")) {
            token = authorization.substring(7);
            userName = jwtUtility.getUsernameFromToken(token);
        }

        if(null!=userName && SecurityContextHolder.getContext().getAuthentication()==null)
        {
            UserDetails userDetails = authenticationService.loadUserByUsername(userName);

            if(jwtUtility.validateToken(token,userDetails) )
            {
                UsernamePasswordAuthenticationToken authenticationToken
                        = new UsernamePasswordAuthenticationToken(userDetails,
                        null,userDetails.getAuthorities());
                authenticationToken.setDetails( new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));

                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }

        }
        filterChain.doFilter(httpServletRequest,httpServletResponse);
    }

*/
}

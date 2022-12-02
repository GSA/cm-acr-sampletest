package gov.gsa.acr.authservice.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@ControllerAdvice
public class GlobalExceptionHandler {
    Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ResponseBody
    @ExceptionHandler(value = {io.jsonwebtoken.SignatureException.class, NullPointerException.class, Exception.class})
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    String globalExceptionHandler(HttpServletRequest request,
                                   HttpServletResponse response, Exception ex) {
        logger.error("API call to "+request.getRequestURL().toString()+" failed.", ex);
        return ex.getMessage();
    }

    @ResponseBody
    @ExceptionHandler(value = {DisabledException.class, BadCredentialsException.class})
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    String failedAuthenticationHandler(HttpServletRequest request,
                                      HttpServletResponse response, Exception ex) {
        logger.error("API call to "+request.getRequestURL().toString()+" failed. " + ex.getMessage());
        return ex.getMessage();
    }

}

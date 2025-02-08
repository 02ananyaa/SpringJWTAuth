package com.jwt.security.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
	 Logger logger = LoggerFactory.getLogger(TestController.class);

	    @GetMapping("/test")
	    public String test() {
	        this.logger.warn("This is working message");
	        return "Testing message";
	    }
}

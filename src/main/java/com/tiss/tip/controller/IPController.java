package com.tiss.tip.controller;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.fasterxml.jackson.databind.JsonNode;
import com.tiss.tip.service.IPService;

@Controller
@RequestMapping("/ip")
public class IPController {

	private static final Logger logger = LoggerFactory.getLogger(IPController.class);

	@Autowired
	private IPService ipService;

	@RequestMapping(value = "/{ip}/analysis", method = RequestMethod.GET)
	public @ResponseBody JsonNode getIPSummary(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @PathVariable String ip) {
		logger.info("Start getIPSummary");
		return ipService.getIPSummary(ip);
	}

	@RequestMapping(value = "/{ip}/history", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getIPHistory(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @PathVariable String ip,
			@RequestParam(required = false, defaultValue = "10") int size) {
		logger.info("Start getIPSummary");
		return ipService.getIPHistory(from, to, ip, size);
	}
	
	@RequestMapping(value = "/{ip}/geo-info", method = RequestMethod.GET)
	public @ResponseBody JsonNode getIPGeoInfo(@PathVariable String ip) {
		logger.info("Start getIPGeoInfo");
		return ipService.getIPGeoInfo(ip);
	}
	
	@RequestMapping(value = "/{ip}/activity-pulse", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getIPActivityPulse(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @PathVariable String ip) {
		logger.info("Start getIPSummary");
		return ipService.getIPActivityTimeline(from, to, ip);
	}
	
	@RequestMapping(value = "/{ip}/activity-summary", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getIPActivity(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @PathVariable String ip) {
		logger.info("Start getIPSummary");
		return ipService.getIPActivitySummary(from, to, ip);
	}
	
	@RequestMapping(value = "/{ip}/probing-attempts", method = RequestMethod.GET)
	public @ResponseBody JsonNode getIPProbingAttemptsCount(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @PathVariable String ip) {
		logger.info("Start getIPSummary");
		return ipService.getIPProbingAttempts(from, to, ip);
	}

}

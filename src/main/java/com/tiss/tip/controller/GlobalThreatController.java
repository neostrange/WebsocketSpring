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
import com.tiss.tip.service.GlobalThreatService;
import com.tiss.tip.service.IncidentService;
import com.tiss.tip.service.MalwareIncidentService;
import com.tiss.tip.service.NetworkIncidentService;

@Controller
@RequestMapping("/global")
public class GlobalThreatController {

	@Autowired
	private IncidentService incidentService;

	@Autowired
	private GlobalThreatService globalService;

	@Autowired
	private MalwareIncidentService malIncidentService;

	@Autowired
	private NetworkIncidentService netIncidentService;

	private static final Logger logger = LoggerFactory.getLogger(GlobalThreatController.class);

	@RequestMapping(value = "/attacking-countries", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getAttackCountsPerCountry(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "0") int size) {
		logger.info("Start getAttackCountsPerCountry");
		return incidentService.getTopCountry("all", from, to, size);
	}

	@RequestMapping(value = "/country/{countryCode}/attack-counts", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getAttackingCountries(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @PathVariable String countryCode) {
		logger.info("Start getAttackCountsPerCountry");
		return globalService.getGlobalAttackSummary(from, to, countryCode);
	}

	@RequestMapping(value = "/country/{countryCode}/attacks/{attackType}/summary", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getAttackTypeSummary(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @PathVariable String countryCode,
			@PathVariable String attackType) {
		logger.info("Start getAttackTypeSummary");
		return globalService.getAttackSummary(from, to, countryCode, attackType);
	}

	@RequestMapping(value = "/country/{countryCode}/attacks/{attackType}/ip-geopoints", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getIPGeo(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @PathVariable String countryCode,
			@PathVariable String attackType) {
		logger.info("Start getIPGeo");
		return globalService.getIPandGeoLoc(from, to, countryCode, attackType);
	}

	@RequestMapping(value = "/country/{countryCode}/attacks/malware/{mal}", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getMalwareHashes(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "0") int size,
			@PathVariable String countryCode, @PathVariable String mal) {
		logger.info("Start getSshCountsCountry");
		return malIncidentService.getMalwareHashes(mal, from, to, size, countryCode);
	}


}

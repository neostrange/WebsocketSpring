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
import com.tiss.tip.service.SshIncidentService;

@Controller
@RequestMapping("/global")
public class GlobalThreatController {

	@Autowired
	private IncidentService incidentService;

	@Autowired
	private GlobalThreatService globalService;

	@Autowired
	private MalwareIncidentService malIncidentService;

//	@Autowired
//	private NetworkIncidentService netIncidentService;
//	@Autowired
//	private SshIncidentService sshService;

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
			@PathVariable String attackType, @RequestParam(required = false, defaultValue = "10") int size, @RequestParam(required = false, defaultValue = "100") int minCount) {
		logger.info("Start getIPGeo");
		return globalService.getIPandGeoLoc(from, to, countryCode, size, minCount, attackType);
	}

	@RequestMapping(value = "/country/{countryCode}/attacks/malware/hashes/{mal}/", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getMalwareHashes(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "0") int size,
			@PathVariable String countryCode, @PathVariable String mal) {
		logger.info("Start getSshCountsCountry");
		return malIncidentService.getMalwareHashes(mal, from, to, size, countryCode);
	}
	
	@RequestMapping(value = "/country/{countryCode}/attacks/ssh/usernames", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getSSHUsernames(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "10") int size,
			@PathVariable String countryCode) {
		logger.info("Start getSSHUsernames");
		return globalService.getSSHUsernamesForCountry(from, to, countryCode, size);
	}

	@RequestMapping(value = "/country/{countryCode}/attacks/ssh/passwords", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getSSHPasswords(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "10") int size,
			@PathVariable String countryCode) {
		logger.info("Start getSSHPasswords");
		return globalService.getSSHPasswordsForCountry(from, to, countryCode, size);
	}

	@RequestMapping(value = "/country/{countryCode}/attacks/ssh/tools", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getSSHTools(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "10") int size,
			@PathVariable String countryCode) {
		logger.info("Start getSSHTools");
		return globalService.getSSHToolsForCountry(from, to, countryCode, size);
	}

	@RequestMapping(value = "/country/{countryCode}/attacks/ssh/inputs", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getSSHInputs(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "10") int size,
			@PathVariable String countryCode) {
		logger.info("Start getSSHInputs");
		return globalService.getSSHInputsForCountry(from, to, countryCode, size);
	}

	@RequestMapping(value = "/country/{countryCode}/attacks/sip/tools", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getSipTools(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "10") int size,
			@PathVariable String countryCode) {
		logger.info("Start getSipTools");
		return globalService.getTopSipTools(from, to, size, countryCode);
	}

	@RequestMapping(value = "/country/{countryCode}/attacks/sip/methods", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getSipMethods(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "10") int size,
			@PathVariable String countryCode) {
		logger.info("Start getSipMethods");
		return globalService.getTopSipMethods(from, to, size, countryCode);
	}

	@RequestMapping(value = "/country/{countryCode}/attacks/sip/ack-flooding-ips", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getSipAckFloodingServers(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "10") int size,
			@PathVariable String countryCode) {
		logger.info("Start getSipAckFloodingServers");
		return globalService.getSipAckFloodingAttacks(from, to, size, countryCode);
	}

	@RequestMapping(value = "/country/{countryCode}/attacks/sip/options-flooding-ips", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getSipOptionsFloodingServers(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "10") int size,
			@PathVariable String countryCode) {
		logger.info("Start getSipOptionsFloodingServers");
		return globalService.getSipOptionsFloodingAttacks(from, to, size, countryCode);
	}

	@RequestMapping(value = "/country/{countryCode}/attacks/sip/registrar-flooding-ips", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getSipRegistrarFloodingServers(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "10") int size,
			@PathVariable String countryCode) {
		logger.info("Start getSipRegistrarFloodingServers");
		return globalService.getSipRegistrarFloodingAttacks(from, to, size, countryCode);
	}

	@RequestMapping(value = "/country/{countryCode}/attacks/sip/proxy-flooding-ips", method = RequestMethod.GET)
	public @ResponseBody List<JsonNode> getSipProxyFloodingServers(@RequestParam(required = false) String from,
			@RequestParam(required = false) String to, @RequestParam(required = false, defaultValue = "10") int size,
			@PathVariable String countryCode) {
		logger.info("Start getSipProxyFloodingServers");
		return globalService.getSipProxyFloodingAttacks(from, to, size, countryCode);
	}

}

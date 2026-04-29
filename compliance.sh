#!/bin/bash
# ──────────────────────────────────────────────────────────────────────
# Engram Compliance Oracle — Interaction Script
# Contract: CCDAXPPXNXCM25QHYVEWDYBU3FJTNU6Z6BYCHTRRHJEXU6RGVD32PWQF
# Network:  Stellar Testnet
# Version:  v0.6.0 (Taint Propagation + Agent Consensus + Merkle)
# ──────────────────────────────────────────────────────────────────────

CONTRACT_ID="CCDAXPPXNXCM25QHYVEWDYBU3FJTNU6Z6BYCHTRRHJEXU6RGVD32PWQF"
NETWORK="testnet"
SOURCE="engram-admin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

invoke() {
  stellar contract invoke \
    --id "$CONTRACT_ID" \
    --source "$SOURCE" \
    --network "$NETWORK" \
    -- "$@" 2>&1 | grep -v "^ℹ️" | grep -v "^$"
}

# ── Commands ───────────────────────────────────────────────────────────

case "$1" in

  # ── Check if an address is sanctioned (Merkle proof verification) ──
  check)
    if [ -z "$2" ]; then
      echo -e "${RED}Usage: $0 check <address>${NC}"
      echo "  Example: $0 check 0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b"
      exit 1
    fi
    echo -e "${CYAN}━━━ Compliance Check ━━━${NC}"
    echo -e "Address: ${BOLD}$2${NC}"
    echo ""

    # Check if flagged by agent consensus
    FLAGGED=$(invoke is_flagged --addr "$2")
    if echo "$FLAGGED" | grep -q "true"; then
      echo -e "${RED}⚠️  STATUS: FLAGGED BY AGENT CONSENSUS${NC}"
    else
      echo -e "${GREEN}✓  Not flagged by agent consensus${NC}"
    fi

    # Check taint status
    TAINTED=$(invoke is_tainted --addr "$2")
    if echo "$TAINTED" | grep -q "true"; then
      SCORE=$(invoke taint_score --addr "$2")
      CHAIN=$(invoke taint_chain --addr "$2")
      HOP=$(invoke taint_hop --addr "$2")
      SOURCE_ADDR=$(invoke taint_source --addr "$2")
      echo -e "${RED}⚠️  TAINTED — Score: ${SCORE}/100 | Chain: ${CHAIN} | Hop: ${HOP}${NC}"
      echo -e "   Source: ${SOURCE_ADDR}"
    else
      echo -e "${GREEN}✓  Not tainted${NC}"
    fi

    # Flag reason
    REASON=$(invoke flag_reason --addr "$2")
    case "$REASON" in
      0) echo -e "\nOverall: ${GREEN}CLEAN${NC}" ;;
      1) echo -e "\nOverall: ${RED}FLAGGED (consensus)${NC}" ;;
      2) echo -e "\nOverall: ${RED}FLAGGED (tainted)${NC}" ;;
      3) echo -e "\nOverall: ${RED}FLAGGED (consensus + tainted)${NC}" ;;
    esac

    # Check report count
    REPORTS=$(invoke reports_for --addr "$2")
    echo -e "Reports: ${YELLOW}${REPORTS}${NC}"

    # Check whitelist
    WHITELISTED=$(invoke is_whitelisted --addr "$2")
    if echo "$WHITELISTED" | grep -q "true"; then
      echo -e "${CYAN}ℹ  Whitelisted (exempt from taint)${NC}"
    fi

    # Show Merkle root info
    ROOT=$(invoke merkle_root)
    if echo "$ROOT" | grep -q "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; then
      echo -e "\n${YELLOW}⚠  No Merkle root set yet — dataset not loaded${NC}"
    else
      echo -e "\nMerkle root: ${CYAN}${ROOT}${NC}"
    fi
    ;;

  # ── Report a suspicious address ────────────────────────────────────
  report)
    if [ -z "$2" ] || [ -z "$3" ]; then
      echo -e "${RED}Usage: $0 report <target_address> <reason>${NC}"
      echo "  Example: $0 report 0xbad...addr \"Known mixer service\""
      exit 1
    fi
    echo -e "${CYAN}━━━ Reporting Address ━━━${NC}"
    echo -e "Target:   ${BOLD}$2${NC}"
    echo -e "Reason:   $3"
    echo -e "Reporter: $SOURCE"
    echo ""

    RESULT=$(invoke report_address \
      --reporter "$SOURCE" \
      --target "$2" \
      --reason "$3")

    if echo "$RESULT" | grep -q "Error"; then
      echo -e "${RED}✗ Report failed:${NC}"
      echo "$RESULT"
    else
      echo -e "${GREEN}✓ Report submitted${NC}"
      echo -e "Report ID: ${BOLD}${RESULT}${NC}"

      # Show updated report count
      REPORTS=$(invoke reports_for --addr "$2")
      THRESHOLD=$(invoke report_threshold)
      echo -e "Reports for this address: ${YELLOW}${REPORTS}${NC} / ${THRESHOLD} threshold"

      FLAGGED=$(invoke is_flagged --addr "$2")
      if echo "$FLAGGED" | grep -q "true"; then
        echo -e "${RED}⚡ THRESHOLD REACHED — Address auto-flagged!${NC}"
      fi
    fi
    ;;

  # ── View contract status ───────────────────────────────────────────
  status)
    echo -e "${CYAN}━━━ Engram Compliance Oracle ━━━${NC}"
    echo -e "Contract: ${BOLD}${CONTRACT_ID}${NC}"
    echo -e "Network:  ${NETWORK}"
    echo ""

    OWNER=$(invoke owner)
    OPERATOR=$(invoke operator)
    ENTITIES=$(invoke entity_count)
    REPORTS=$(invoke report_count)
    THRESHOLD=$(invoke report_threshold)
    ROOT=$(invoke merkle_root)
    HASH=$(invoke data_hash)
    UPDATED=$(invoke last_updated)

    echo -e "Owner:           ${OWNER}"
    echo -e "Operator:        ${OPERATOR}"
    echo -e "Entity Count:    ${BOLD}${ENTITIES}${NC}"
    echo -e "Report Count:    ${BOLD}${REPORTS}${NC}"
    echo -e "Report Threshold:${BOLD} ${THRESHOLD}${NC}"
    echo -e "Merkle Root:     ${CYAN}${ROOT}${NC}"
    echo -e "Data Hash:       ${HASH}"
    echo -e "Last Updated:    ${UPDATED}"
    ;;

  # ── View a specific report ────────────────────────────────────────
  get-report)
    if [ -z "$2" ]; then
      echo -e "${RED}Usage: $0 get-report <report_id>${NC}"
      exit 1
    fi
    echo -e "${CYAN}━━━ Report #$2 ━━━${NC}"
    invoke get_report --report_id "$2"
    ;;

  # ── Set report threshold (operator only) ───────────────────────────
  set-threshold)
    if [ -z "$2" ]; then
      echo -e "${RED}Usage: $0 set-threshold <number>${NC}"
      exit 1
    fi
    echo -e "${CYAN}Setting threshold to $2...${NC}"
    invoke set_report_threshold --threshold "$2"
    echo -e "${GREEN}✓ Threshold updated${NC}"
    ;;

  # ── Taint: set taint for an address ─────────────────────────────────
  taint)
    if [ -z "$2" ] || [ -z "$3" ] || [ -z "$4" ] || [ -z "$5" ]; then
      echo -e "${RED}Usage: $0 taint <address> <score> <source_addr> <hop> [chain]${NC}"
      echo "  Example: $0 taint 0xabc123... 72 GABC123... 1 stellar"
      exit 1
    fi
    CHAIN=${6:-stellar}
    echo -e "${CYAN}━━━ Setting Taint ━━━${NC}"
    echo -e "Target: ${BOLD}$2${NC}"
    echo -e "Score:  $3/100"
    echo -e "Source: $4"
    echo -e "Hop:    $5"
    echo -e "Chain:  $CHAIN"
    echo ""
    RESULT=$(invoke set_taint --addr "$2" --score "$3" --source "$4" --hop "$5" --chain "$CHAIN")
    echo -e "${GREEN}✓ Taint set${NC}"
    echo "$RESULT"
    ;;

  # ── Clear taint ─────────────────────────────────────────────────────
  clear-taint)
    if [ -z "$2" ]; then
      echo -e "${RED}Usage: $0 clear-taint <address>${NC}"
      exit 1
    fi
    echo -e "${CYAN}━━━ Clearing Taint ━━━${NC}"
    RESULT=$(invoke clear_taint --addr "$2")
    echo -e "${GREEN}✓ Taint cleared for $2${NC}"
    echo "$RESULT"
    ;;

  # ── Whitelist management ────────────────────────────────────────────
  whitelist)
    if [ -z "$2" ]; then
      echo -e "${RED}Usage: $0 whitelist <add|remove|check> <address>${NC}"
      exit 1
    fi
    case "$2" in
      add)
        RESULT=$(invoke whitelist_address --addr "$3")
        echo -e "${GREEN}✓ Whitelisted: $3${NC}"
        echo "$RESULT"
        ;;
      remove)
        RESULT=$(invoke unwhitelist_address --addr "$3")
        echo -e "${GREEN}✓ Removed from whitelist: $3${NC}"
        echo "$RESULT"
        ;;
      check)
        RESULT=$(invoke is_whitelisted --addr "$3")
        if echo "$RESULT" | grep -q "true"; then
          echo -e "${CYAN}✓ Address is whitelisted${NC}"
        else
          echo -e "${YELLOW}✗ Address is NOT whitelisted${NC}"
        fi
        ;;
      *)
        echo -e "${RED}Usage: $0 whitelist <add|remove|check> <address>${NC}"
        ;;
    esac
    ;;

  # ── Taint config ────────────────────────────────────────────────────
  taint-config)
    echo -e "${CYAN}━━━ Taint Configuration ━━━${NC}"
    CONFIG=$(invoke taint_config)
    echo -e "Config: $CONFIG"
    echo -e "  Format: [min_amount_stroops, max_hops]"
    ;;

  # ── Help ───────────────────────────────────────────────────────────
  *)
    echo -e "${BOLD}Engram Compliance Oracle v0.6.0${NC}"
    echo -e "Contract: ${CYAN}${CONTRACT_ID}${NC}"
    echo ""
    echo -e "${BOLD}Usage:${NC} $0 <command> [args]"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo -e "  ${GREEN}check${NC}          <address>                    Full compliance check"
    echo -e "  ${GREEN}report${NC}         <address> <reason>            Report suspicious address"
    echo -e "  ${GREEN}status${NC}                                      View contract status"
    echo -e "  ${GREEN}get-report${NC}     <id>                          View a specific report"
    echo -e "  ${GREEN}set-threshold${NC}  <n>                           Set auto-flag threshold (operator)"
    echo ""
    echo -e "${BOLD}Taint Propagation:${NC}"
    echo -e "  ${GREEN}taint${NC}          <addr> <score> <src> <hop>     Set taint for address (operator)"
    echo -e "  ${GREEN}clear-taint${NC}    <address>                     Remove taint (operator)"
    echo -e "  ${GREEN}whitelist${NC}      <add|remove|check> <addr>      Manage exchange whitelist"
    echo -e "  ${GREEN}taint-config${NC}                                  View taint thresholds"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  $0 check 0xd882cfc20f52f2599d84b8e8d58c7fb62cfe344b"
    echo "  $0 report 0xbad1234567890abcdef1234567890abcdef123456 \"Known mixer\""
    echo "  $0 taint 0xabc... 72 GABC... 1 stellar"
    echo "  $0 whitelist add GCGNWKCJ3KHRLPM3TM6N7D3W5YKDJFL6A2YCXFXNMRTZ4Q66MEMZ4FI2"
    echo "  $0 taint-config"
    ;;
esac

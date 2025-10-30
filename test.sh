#!/bin/bash
# Comprehensive test runner for Ditto project
# This script runs all tests with coverage and generates reports

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Ditto Comprehensive Test Suite ===${NC}\n"

# Create test output directory
TEST_DIR="test_output"
mkdir -p $TEST_DIR

# Run tests with coverage
echo -e "${YELLOW}Running unit tests with coverage...${NC}"
go test -v -coverprofile=$TEST_DIR/coverage.out -covermode=atomic ./... 2>&1 | tee $TEST_DIR/test.log

# Check if tests passed
if [ $? -eq 0 ]; then
    echo -e "\n${GREEN}✓ All tests passed!${NC}"
else
    echo -e "\n${RED}✗ Some tests failed. Check test.log for details.${NC}"
    exit 1
fi

# Generate coverage report
echo -e "\n${YELLOW}Generating coverage report...${NC}"
go tool cover -html=$TEST_DIR/coverage.out -o $TEST_DIR/coverage.html
go tool cover -func=$TEST_DIR/coverage.out > $TEST_DIR/coverage.txt

# Display coverage summary
echo -e "\n${GREEN}Coverage Summary:${NC}"
cat $TEST_DIR/coverage.txt | tail -1

# Run benchmarks
echo -e "\n${YELLOW}Running benchmarks...${NC}"
go test -bench=. -benchmem ./... 2>&1 | tee $TEST_DIR/benchmark.log

# Run race detector
echo -e "\n${YELLOW}Running race detector...${NC}"
go test -race ./... 2>&1 | tee $TEST_DIR/race.log

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ No race conditions detected${NC}"
else
    echo -e "${RED}✗ Race conditions detected${NC}"
fi

# Run vet
echo -e "\n${YELLOW}Running go vet...${NC}"
go vet ./... 2>&1 | tee $TEST_DIR/vet.log

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ No vet issues found${NC}"
else
    echo -e "${YELLOW}⚠ Some vet issues found (check vet.log)${NC}"
fi

# Run gofmt check
echo -e "\n${YELLOW}Checking code formatting...${NC}"
if gofmt -l . | grep -q .; then
    echo -e "${YELLOW}⚠ Some files are not formatted. Run 'gofmt -w .' to fix.${NC}"
    gofmt -l . | tee $TEST_DIR/gofmt.log
else
    echo -e "${GREEN}✓ All files are properly formatted${NC}"
fi

# Count test files and coverage
TEST_COUNT=$(find . -name "*_test.go" -type f | wc -l)
COVERAGE=$(cat $TEST_DIR/coverage.txt | tail -1 | awk '{print $3}')

echo -e "\n${GREEN}=== Test Summary ===${NC}"
echo "Test files: $TEST_COUNT"
echo "Coverage: $COVERAGE"
echo "Reports saved to: $TEST_DIR/"

# Check if coverage meets threshold
COVERAGE_NUM=$(echo $COVERAGE | sed 's/%//')
if (( $(echo "$COVERAGE_NUM >= 80" | bc -l) )); then
    echo -e "${GREEN}✓ Coverage meets threshold (>=80%)${NC}"
else
    echo -e "${YELLOW}⚠ Coverage below threshold (<80%)${NC}"
fi

echo -e "\n${GREEN}Test suite completed!${NC}"
echo "View coverage report: file://$(pwd)/$TEST_DIR/coverage.html"


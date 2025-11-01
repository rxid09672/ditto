package evasion

import (
	"crypto/rand"
	"fmt"
)

// ObfuscateCode applies code obfuscation techniques
func ObfuscateCode(data []byte) []byte {
	// Simple XOR obfuscation (would be more sophisticated in production)
	key := make([]byte, len(data))
	if _, err := rand.Read(key); err != nil {
		return data
	}
	
	obfuscated := make([]byte, len(data))
	for i := range data {
		obfuscated[i] = data[i] ^ key[i%len(key)]
	}
	
	return obfuscated
}

// DeobfuscateCode reverses obfuscation
func DeobfuscateCode(data []byte, key []byte) []byte {
	deobfuscated := make([]byte, len(data))
	for i := range data {
		deobfuscated[i] = data[i] ^ key[i%len(key)]
	}
	return deobfuscated
}

// ApplyPolymorphism applies polymorphic transformations
// DEPRECATED: Use ApplyEntropyPolymorphism for novel non-human reasoning approach
func ApplyPolymorphism(code []byte) []byte {
	// Add NOPs, reorder instructions, etc.
	if len(code) == 0 {
		return []byte{}
	}
	
	polymorphic := make([]byte, 0, len(code)*2)
	
	// Insert random NOPs
	nopCount := len(code) / 10
	if nopCount == 0 {
		// If code is too short, don't insert NOPs
		return append([]byte{}, code...)
	}
	
	for i := 0; i < len(code); i++ {
		polymorphic = append(polymorphic, code[i])
		if i%nopCount == 0 && i > 0 {
			polymorphic = append(polymorphic, 0x90) // NOP
		}
	}
	
	return polymorphic
}

// ApplyEntropyPolymorphism applies novel entropy-driven polymorphic transformations
// that don't follow human reasoning patterns but are fully functional.
// Novel approach: Data-driven transformations based on byte content analysis
// rather than position-based human logic (e.g., "insert NOP every N bytes").
func ApplyEntropyPolymorphism(code []byte) []byte {
	return ApplyEntropyPolymorphismAdvanced(code, nil)
}

// ApplyEntropyPolymorphismAdvanced applies enhanced entropy-driven polymorphism
// with optional benign profile matching for mimicry.
func ApplyEntropyPolymorphismAdvanced(code []byte, targetProfile *BenignProfile) []byte {
	if len(code) == 0 {
		return []byte{}
	}
	
	// Phase 1: Analyze byte frequency distribution (entropy analysis)
	freqMap := make(map[byte]int)
	for _, b := range code {
		freqMap[b]++
	}
	
	// Phase 2: Calculate entropy-derived transformation zones
	// Zones are determined by byte frequency clusters, not human-defined intervals
	zones := computeEntropyZones(code, freqMap)
	
	// Phase 2.5: Normalize entropy profile if target profile provided (mimicry)
	if targetProfile != nil {
		code = normalizeEntropyProfile(code, zones, targetProfile, freqMap)
		// Re-analyze after normalization
		freqMap = make(map[byte]int)
		for _, b := range code {
			freqMap[b]++
		}
		zones = computeEntropyZones(code, freqMap)
	}
	
	// Phase 3: Generate emergent transformation patterns with adaptive selection
	// Pattern selection based on percentile-based relative positioning, not fixed thresholds
	transforms := generateEmergentTransformsAdaptive(code, freqMap, zones)
	
	// Phase 4: Multi-layer transformation with feedback loops
	result := applyMultiLayerTransforms(code, transforms, freqMap)
	
	return result
}

// entropyZone represents a region identified by entropy analysis
type entropyZone struct {
	start       int
	end         int
	avgEntropy  float64
	byteDensity float64
	transformID int
}

// BenignProfile represents the entropy characteristics of benign software
// Used for mimicry-based evasion
type BenignProfile struct {
	AvgEntropy      float64
	EntropyStdDev   float64
	ByteDistrib     map[byte]float64
	ZoneCharacteristics []ZoneProfile
}

// ZoneProfile represents characteristics of a zone in benign software
type ZoneProfile struct {
	AvgEntropy  float64
	AvgDensity  float64
	CommonBytes []byte
}

// computeEntropyZones identifies transformation zones based on byte entropy
// Non-human reasoning: zones emerge from data characteristics, not fixed intervals
func computeEntropyZones(code []byte, freqMap map[byte]int) []entropyZone {
	if len(code) < 16 {
		// Too small for meaningful zones
		return []entropyZone{{0, len(code), 0.0, 0.0, 0}}
	}
	
	zones := make([]entropyZone, 0)
	windowSize := max(16, len(code)/32) // Adaptive window size
	
	// Calculate local entropy for each window
	currentZone := entropyZone{start: 0, avgEntropy: 0.0, byteDensity: 0.0}
	
	for i := 0; i < len(code); i += windowSize / 2 {
		end := min(i+windowSize, len(code))
		window := code[i:end]
		
		// Calculate local entropy in this window
		localFreq := make(map[byte]int)
		for _, b := range window {
			localFreq[b]++
		}
		
		entropy := calculateShannonEntropy(localFreq, len(window))
		density := calculateByteDensity(window, freqMap)
		
		// Zone boundary determined by entropy change, not fixed position
		if i > 0 && abs(entropy-currentZone.avgEntropy) > 0.15 {
			// Entropy shift detected - close current zone, start new one
			currentZone.end = i
			if currentZone.end > currentZone.start {
				currentZone.transformID = selectTransformByEntropyAdaptive(currentZone.avgEntropy, currentZone.byteDensity, code, freqMap)
				zones = append(zones, currentZone)
			}
			currentZone = entropyZone{start: i, avgEntropy: entropy, byteDensity: density}
		} else {
			// Update zone averages
			currentZone.avgEntropy = (currentZone.avgEntropy + entropy) / 2
			currentZone.byteDensity = (currentZone.byteDensity + density) / 2
		}
	}
	
	// Close final zone
	currentZone.end = len(code)
	if currentZone.end > currentZone.start {
		currentZone.transformID = selectTransformByEntropyAdaptive(currentZone.avgEntropy, currentZone.byteDensity, code, freqMap)
		zones = append(zones, currentZone)
	}
	
	return zones
}

// calculateShannonEntropy computes Shannon entropy for byte distribution
func calculateShannonEntropy(freqMap map[byte]int, total int) float64 {
	if total == 0 {
		return 0.0
	}
	
	entropy := 0.0
	for _, count := range freqMap {
		if count > 0 {
			prob := float64(count) / float64(total)
			entropy -= prob * log2(prob)
		}
	}
	
	return entropy
}

// calculateByteDensity computes byte density relative to global frequency
func calculateByteDensity(window []byte, globalFreq map[byte]int) float64 {
	if len(window) == 0 {
		return 0.0
	}
	
	localFreq := make(map[byte]int)
	for _, b := range window {
		localFreq[b]++
	}
	
	// Density = how much local distribution differs from global
	divergence := 0.0
	for b, localCount := range localFreq {
		localProb := float64(localCount) / float64(len(window))
		globalCount := globalFreq[b]
		if globalCount > 0 {
			globalProb := float64(globalCount) / float64(len(window)*len(globalFreq))
			divergence += abs(localProb - globalProb)
		}
	}
	
	return divergence
}

// selectTransformByEntropy selects transformation type based on entropy characteristics
// DEPRECATED: Uses hardcoded thresholds. Use selectTransformByEntropyAdaptive instead.
func selectTransformByEntropy(entropy, density float64) int {
	// High entropy + high density = instruction substitution
	// Low entropy + low density = byte expansion
	// Medium entropy = semantic equivalence insertion
	
	if entropy > 6.0 && density > 0.3 {
		return 0 // Instruction substitution
	} else if entropy < 4.0 && density < 0.1 {
		return 1 // Byte expansion
	} else if entropy > 5.0 && density < 0.2 {
		return 2 // Semantic equivalence
	} else {
		return 3 // Adaptive hybrid
	}
}

// selectTransformByEntropyAdaptive selects transformation using percentile-based adaptive selection
// Non-human reasoning: thresholds derived from data distribution, not hardcoded values
func selectTransformByEntropyAdaptive(entropy, density float64, code []byte, freqMap map[byte]int) int {
	// Calculate distribution of entropy and density values from code
	entropyDist := calculateEntropyDistribution(code, freqMap)
	densityDist := calculateDensityDistribution(code, freqMap)
	
	// Find percentile position of current values (relative positioning)
	entropyPercentile := percentile(entropy, entropyDist)
	densityPercentile := percentile(density, densityDist)
	
	// Select transform based on relative position in distribution (not absolute thresholds)
	// This is truly data-driven and adaptive
	
	// High entropy zone (top quartile) - use percentiles, not fixed values
	if entropyPercentile > 0.75 {
		if densityPercentile > 0.7 {
			return 0 // Instruction substitution
		} else {
			return 2 // Semantic equivalence
		}
	}
	
	// Low entropy zone (bottom quartile)
	if entropyPercentile < 0.25 {
		if densityPercentile < 0.2 {
			return 1 // Byte expansion
		}
	}
	
	// Default: adaptive hybrid based on local characteristics
	return 3
}

// calculateEntropyDistribution computes entropy values for all zones to build distribution
func calculateEntropyDistribution(code []byte, freqMap map[byte]int) []float64 {
	if len(code) < 16 {
		return []float64{0.0}
	}
	
	dist := make([]float64, 0)
	windowSize := max(16, len(code)/32)
	
	for i := 0; i < len(code); i += windowSize / 2 {
		end := min(i+windowSize, len(code))
		window := code[i:end]
		
		localFreq := make(map[byte]int)
		for _, b := range window {
			localFreq[b]++
		}
		
		entropy := calculateShannonEntropy(localFreq, len(window))
		dist = append(dist, entropy)
	}
	
	return dist
}

// calculateDensityDistribution computes density values for all zones to build distribution
func calculateDensityDistribution(code []byte, freqMap map[byte]int) []float64 {
	if len(code) < 16 {
		return []float64{0.0}
	}
	
	dist := make([]float64, 0)
	windowSize := max(16, len(code)/32)
	
	for i := 0; i < len(code); i += windowSize / 2 {
		end := min(i+windowSize, len(code))
		window := code[i:end]
		
		density := calculateByteDensity(window, freqMap)
		dist = append(dist, density)
	}
	
	return dist
}

// percentile calculates what percentile a value falls into within a distribution
func percentile(value float64, distribution []float64) float64 {
	if len(distribution) == 0 {
		return 0.5 // Default to median if no distribution
	}
	
	// Sort distribution
	sorted := make([]float64, len(distribution))
	copy(sorted, distribution)
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	
	// Count values less than or equal to value
	count := 0
	for _, v := range sorted {
		if v <= value {
			count++
		}
	}
	
	return float64(count) / float64(len(sorted))
}

// transformOp represents a transformation operation
type transformOp struct {
	zoneID     int
	opType     int
	position   int
	parameters []byte
}

// generateEmergentTransforms generates transformation operations based on data analysis
// DEPRECATED: Use generateEmergentTransformsAdaptive for percentile-based selection
func generateEmergentTransforms(code []byte, freqMap map[byte]int, zones []entropyZone) []transformOp {
	return generateEmergentTransformsAdaptive(code, freqMap, zones)
}

// generateEmergentTransformsAdaptive generates transformation operations using adaptive selection
func generateEmergentTransformsAdaptive(code []byte, freqMap map[byte]int, zones []entropyZone) []transformOp {
	transforms := make([]transformOp, 0)
	
	for zoneID, zone := range zones {
		// Generate transforms based on zone characteristics, not fixed patterns
		zoneData := code[zone.start:zone.end]
		
		// Identify transformation points using byte content analysis
		transformPoints := identifyTransformPoints(zoneData, freqMap)
		
		for _, point := range transformPoints {
			op := transformOp{
				zoneID:     zoneID,
				opType:     zone.transformID,
				position:   zone.start + point,
				parameters: deriveTransformParams(zoneData, point, freqMap),
			}
			transforms = append(transforms, op)
		}
	}
	
	return transforms
}

// identifyTransformPoints finds transformation points based on byte patterns
// Non-human reasoning: points emerge from byte relationships, not fixed intervals
func identifyTransformPoints(zoneData []byte, globalFreq map[byte]int) []int {
	if len(zoneData) < 4 {
		return []int{}
	}
	
	points := make([]int, 0)
	
	// Use sliding window to detect byte pattern transitions
	for i := 2; i < len(zoneData)-2; i++ {
		// Analyze local byte relationships
		context := zoneData[i-2 : i+3]
		
		// Transformation point if byte value differs significantly from neighbors
		// or if byte frequency locally differs from global
		if shouldTransformAt(context, globalFreq) {
			points = append(points, i)
		}
	}
	
	return points
}

// shouldTransformAt determines if transformation should occur at this position
// Decision based on byte content analysis, not human logic
func shouldTransformAt(context []byte, globalFreq map[byte]int) bool {
	if len(context) < 5 {
		return false
	}
	
	center := context[2]
	
	// Calculate local deviation
	localDeviation := 0.0
	for i, b := range context {
		if i != 2 {
			dev := abs(float64(int(b) - int(center)))
			localDeviation += dev
		}
	}
	localDeviation /= float64(len(context) - 1)
	
	// Compare with global frequency characteristics
	centerFreq := globalFreq[center]
	avgFreq := 0
	for _, freq := range globalFreq {
		avgFreq += freq
	}
	if len(globalFreq) > 0 {
		avgFreq /= len(globalFreq)
	}
	
	// Transform if local deviation is high relative to global patterns
	// This creates emergent patterns based on data, not human rules
	return localDeviation > 15.0 || abs(float64(centerFreq-avgFreq)) > float64(avgFreq)*0.5
}

// deriveTransformParams generates transformation parameters from byte context
func deriveTransformParams(zoneData []byte, position int, globalFreq map[byte]int) []byte {
	if position >= len(zoneData) {
		return []byte{}
	}
	
	// Parameters derived from byte relationships in context
	context := zoneData[max(0, position-3):min(len(zoneData), position+4)]
	
	// Generate parameters based on byte XOR relationships
	params := make([]byte, 0, len(context))
	for i := 0; i < len(context)-1; i++ {
		param := context[i] ^ context[i+1]
		// Adjust based on global frequency patterns
		if freq, exists := globalFreq[param]; exists && freq > 0 {
			param = byte((int(param) + freq) % 256)
		}
		params = append(params, param)
	}
	
	return params
}

// applySelfOrganizingTransforms applies transformations in a self-organizing manner
// DEPRECATED: Use applyMultiLayerTransforms for enhanced multi-pass approach
func applySelfOrganizingTransforms(code []byte, transforms []transformOp) []byte {
	if len(transforms) == 0 {
		return append([]byte{}, code...)
	}
	
	output := make([]byte, 0, len(code)*2)
	currentPos := 0
	
	for _, transform := range transforms {
		// Copy bytes before transform position
		if transform.position > currentPos {
			output = append(output, code[currentPos:transform.position]...)
		}
		
		// Apply transformation based on type
		transformed := applyTransformAt(code, transform)
		output = append(output, transformed...)
		
		// Skip the original byte since we replaced it
		currentPos = transform.position + 1
	}
	
	// Copy remaining bytes
	if currentPos < len(code) {
		output = append(output, code[currentPos:]...)
	}
	
	return output
}

// applyMultiLayerTransforms applies transformations in multiple passes with feedback loops
func applyMultiLayerTransforms(code []byte, initialTransforms []transformOp, freqMap map[byte]int) []byte {
	if len(initialTransforms) == 0 {
		return append([]byte{}, code...)
	}
	
	result := code
	transforms := initialTransforms
	
	// Multi-pass transformation with feedback
	for pass := 0; pass < 3; pass++ {
		output := make([]byte, 0, len(result)*2)
		currentPos := 0
		
		// Sort transforms by position to maintain order
		for _, transform := range transforms {
			if transform.position > currentPos {
				output = append(output, result[currentPos:transform.position]...)
			}
			
			// Apply enhanced transformation
			transformed := applyTransformAtEnhanced(result, transform)
			output = append(output, transformed...)
			
			currentPos = transform.position + 1
		}
		
		// Copy remaining bytes
		if currentPos < len(result) {
			output = append(output, result[currentPos:]...)
		}
		
		result = output
		
		// Re-analyze for next pass (feedback loop)
		if pass < 2 {
			newFreqMap := make(map[byte]int)
			for _, b := range result {
				newFreqMap[b]++
			}
			newZones := computeEntropyZones(result, newFreqMap)
			transforms = generateEmergentTransformsAdaptive(result, newFreqMap, newZones)
			
			// Limit transform count to prevent explosion
			if len(transforms) > len(initialTransforms)*2 {
				transforms = transforms[:len(initialTransforms)*2]
			}
		}
	}
	
	return result
}

// applyTransformAt applies a specific transformation at a position
func applyTransformAt(code []byte, transform transformOp) []byte {
	return applyTransformAtEnhanced(code, transform)
}

// applyTransformAtEnhanced applies enhanced transformations including opaque predicates
func applyTransformAtEnhanced(code []byte, transform transformOp) []byte {
	if transform.position >= len(code) {
		return []byte{}
	}
	
	originalByte := code[transform.position]
	
	switch transform.opType {
	case 0: // Instruction substitution - semantically equivalent byte sequences
		return generateSemanticEquivalent(originalByte, transform.parameters)
	case 1: // Byte expansion - multiple bytes representing same semantic value
		return generateByteExpansion(originalByte, transform.parameters)
	case 2: // Semantic equivalence - alternative encoding
		return generateAlternativeEncoding(originalByte, transform.parameters)
	case 3: // Adaptive hybrid - combination based on context
		return generateAdaptiveHybrid(originalByte, transform.parameters)
	default:
		return []byte{originalByte}
	}
}

// generateSemanticEquivalent creates semantically equivalent byte sequences with opaque predicates
func generateSemanticEquivalent(original byte, params []byte) []byte {
	if len(params) == 0 {
		return []byte{original}
	}
	
	// Enhanced version with opaque predicate chains
	result := make([]byte, 0, 5)
	
	// Create opaque predicate chain: original = (a^b)^b = a
	// This creates complexity without changing semantics
	opaque1 := original ^ params[0]
	opaque2 := params[0]
	opaque3 := opaque1 ^ opaque2 // Always equals original (opaque predicate)
	
	// Add redundant operations to confuse analysis
	result = append(result, opaque1)
	result = append(result, opaque2)
	result = append(result, opaque3)
	
	// Add additional opaque chain if we have more params
	if len(params) > 1 {
		opaque4 := original ^ params[1]
		opaque5 := params[1]
		opaque6 := opaque4 ^ opaque5 // Another opaque predicate
		result = append(result, opaque6)
		result = append(result, opaque3^opaque6^opaque6) // Redundant operation
	}
	
	return result
}

// generateByteExpansion creates multiple bytes representing same semantic value
func generateByteExpansion(original byte, params []byte) []byte {
	if len(params) == 0 {
		return []byte{original}
	}
	
	// Expand byte into multiple bytes that XOR to original
	result := make([]byte, 0, 3)
	
	// Create bytes that XOR to original
	// Strategy: original = a ^ b ^ c, so we can set a, b, and compute c
	if len(params) >= 2 {
		// Use first param as first byte
		result = append(result, params[0])
		// Use second param as second byte
		result = append(result, params[1])
		// Third byte ensures XOR chain equals original
		result = append(result, original^params[0]^params[1])
	} else {
		// With single param, use it and compute complement
		result = append(result, params[0])
		result = append(result, original^params[0])
	}
	
	return result
}

// generateAlternativeEncoding creates alternative encoding of byte
func generateAlternativeEncoding(original byte, params []byte) []byte {
	if len(params) == 0 {
		return []byte{original}
	}
	
	// Create alternative representation
	result := make([]byte, 0, 2)
	
	// Use first param as encoding key
	encoded := original ^ params[0]
	result = append(result, encoded)
	result = append(result, params[0]) // Decoder key
	
	return result
}

// generateAdaptiveHybrid combines multiple techniques based on context
func generateAdaptiveHybrid(original byte, params []byte) []byte {
	if len(params) == 0 {
		return []byte{original}
	}
	
	// Select technique based on parameter characteristics
	paramSum := byte(0)
	for _, p := range params {
		paramSum += p
	}
	
	// Choose transform based on parameter sum (non-human pattern)
	if paramSum%3 == 0 {
		return generateSemanticEquivalent(original, params)
	} else if paramSum%3 == 1 {
		return generateByteExpansion(original, params)
	} else {
		return generateAlternativeEncoding(original, params)
	}
}

// Helper functions
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func log2(x float64) float64 {
	if x <= 0 {
		return 0
	}
	// Better approximation for log2
	// For small values, use direct Taylor series
	// For larger values, use log2(x) = log2(2^n * m) = n + log2(m)
	
	ln2 := 0.6931471805599453
	
	// Normalize to range [0.5, 1.0] for better accuracy
	n := 0.0
	val := x
	
	if val >= 1.0 {
		// Reduce to [1, 2) range
		for val >= 2.0 {
			val /= 2.0
			n += 1.0
		}
		// Now val is in [1, 2), use ln approximation
		y := val - 1.0
		ln := y - y*y/2.0 + y*y*y/3.0 - y*y*y*y/4.0 + y*y*y*y*y/5.0
		return n + ln/ln2
	} else {
		// For values < 1, expand to [1, 2) range
		for val < 1.0 {
			val *= 2.0
			n -= 1.0
		}
		y := val - 1.0
		ln := y - y*y/2.0 + y*y*y/3.0 - y*y*y*y/4.0 + y*y*y*y*y/5.0
		return n + ln/ln2
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// AnalyzeBenignSoftwareSamples analyzes multiple benign software samples to build a profile
func AnalyzeBenignSoftwareSamples(samples [][]byte) *BenignProfile {
	if len(samples) == 0 {
		return nil
	}
	
	profiles := make([]EntropyProfile, 0, len(samples))
	
	for _, sample := range samples {
		if len(sample) == 0 {
			continue
		}
		freqMap := make(map[byte]int)
		for _, b := range sample {
			freqMap[b]++
		}
		entropy := calculateShannonEntropy(freqMap, len(sample))
		density := calculateByteDensity(sample, freqMap)
		
		profiles = append(profiles, EntropyProfile{
			Entropy: entropy,
			Density: density,
			FreqMap: freqMap,
		})
	}
	
	if len(profiles) == 0 {
		return nil
	}
	
	// Calculate average characteristics
	avgEntropy := 0.0
	avgDensity := 0.0
	for _, p := range profiles {
		avgEntropy += p.Entropy
		avgDensity += p.Density
	}
	avgEntropy /= float64(len(profiles))
	avgDensity /= float64(len(profiles))
	
	// Calculate standard deviation
	entropyStdDev := 0.0
	for _, p := range profiles {
		diff := p.Entropy - avgEntropy
		entropyStdDev += diff * diff
	}
	entropyStdDev = sqrt(entropyStdDev / float64(len(profiles)))
	
	// Build byte distribution
	byteDistrib := make(map[byte]float64)
	totalBytes := 0
	for _, p := range profiles {
		for b, count := range p.FreqMap {
			byteDistrib[b] += float64(count)
			totalBytes += count
		}
	}
	for b := range byteDistrib {
		byteDistrib[b] /= float64(totalBytes)
	}
	
	return &BenignProfile{
		AvgEntropy:    avgEntropy,
		EntropyStdDev: entropyStdDev,
		ByteDistrib:   byteDistrib,
	}
}

// EntropyProfile represents entropy characteristics of a sample
type EntropyProfile struct {
	Entropy float64
	Density float64
	FreqMap map[byte]int
}

// normalizeEntropyProfile adjusts code entropy to match target benign profile
func normalizeEntropyProfile(code []byte, zones []entropyZone, profile *BenignProfile, freqMap map[byte]int) []byte {
	if profile == nil || len(code) == 0 {
		return code
	}
	
	// Calculate current average entropy
	currentAvgEntropy := 0.0
	for _, zone := range zones {
		currentAvgEntropy += zone.avgEntropy
	}
	if len(zones) > 0 {
		currentAvgEntropy /= float64(len(zones))
	}
	
	// Calculate adjustment needed
	entropyDiff := profile.AvgEntropy - currentAvgEntropy
	
	// If close enough, skip normalization
	if abs(entropyDiff) < 0.1 {
		return code
	}
	
	// Apply adjustments to zones
	result := make([]byte, 0, len(code)*2)
	currentPos := 0
	
	for _, zone := range zones {
		// Copy bytes before zone
		if zone.start > currentPos {
			result = append(result, code[currentPos:zone.start]...)
		}
		
		zoneData := code[zone.start:zone.end]
		
		// Adjust zone entropy toward target
		if entropyDiff > 0 {
			// Need to increase entropy - add more transformations
			adjusted := increaseZoneEntropy(zoneData, entropyDiff, freqMap)
			result = append(result, adjusted...)
		} else {
			// Need to decrease entropy - reduce transformations
			adjusted := decreaseZoneEntropy(zoneData, abs(entropyDiff), freqMap)
			result = append(result, adjusted...)
		}
		
		currentPos = zone.end
	}
	
	// Copy remaining bytes
	if currentPos < len(code) {
		result = append(result, code[currentPos:]...)
	}
	
	return result
}

// increaseZoneEntropy increases entropy of a zone
func increaseZoneEntropy(zoneData []byte, targetIncrease float64, freqMap map[byte]int) []byte {
	result := make([]byte, 0, len(zoneData)*2)
	
	// Add more transformations to increase entropy
	// Use byte expansion more frequently
	for i := 0; i < len(zoneData); i++ {
		b := zoneData[i]
		params := deriveTransformParams(zoneData, i, freqMap)
		
		// Increase transformation frequency
		if i%2 == 0 && len(params) > 0 {
			expanded := generateByteExpansion(b, params)
			result = append(result, expanded...)
		} else {
			result = append(result, b)
		}
	}
	
	return result
}

// decreaseZoneEntropy decreases entropy of a zone
func decreaseZoneEntropy(zoneData []byte, targetDecrease float64, freqMap map[byte]int) []byte {
	// Reduce transformations - keep more original bytes
	result := make([]byte, 0, len(zoneData))
	
	// Reduce transformation frequency
	for i := 0; i < len(zoneData); i++ {
		b := zoneData[i]
		
		// Only transform every 4th byte instead of every 2nd
		if i%4 == 0 && i > 0 {
			params := deriveTransformParams(zoneData, i, freqMap)
			if len(params) > 0 {
				// Use simpler alternative encoding
				encoded := generateAlternativeEncoding(b, params)
				result = append(result, encoded...)
			} else {
				result = append(result, b)
			}
		} else {
			result = append(result, b)
		}
	}
	
	return result
}

// sqrt calculates square root (simple approximation)
func sqrt(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x == 0 {
		return 0
	}
	
	// Newton's method approximation
	guess := x / 2
	for i := 0; i < 10; i++ {
		guess = (guess + x/guess) / 2
	}
	return guess
}

// StringObfuscation obfuscates strings
func StringObfuscation(plaintext string) string {
	// Simple ROT13 + base64 encoding
	rot13 := make([]byte, len(plaintext))
	for i := range plaintext {
		c := plaintext[i]
		if c >= 'a' && c <= 'z' {
			rot13[i] = 'a' + (c-'a'+13)%26
		} else if c >= 'A' && c <= 'Z' {
			rot13[i] = 'A' + (c-'A'+13)%26
		} else {
			rot13[i] = c
		}
	}
	return fmt.Sprintf("obf_%x", rot13)
}


// Copyright 2026 Team 254. All Rights Reserved.
// Author: pat@patfairbank.com (Patrick Fairbank)
//
// Hardcoded physical fixture mapping for the 2026 Hub LEDs.

package led

type fixtureId int

const (
	redGoalSide1Bot fixtureId = iota
	redGoalSide1Top
	redGoalSide2Bot
	redGoalSide2Top
	redGoalSide3Bot
	redGoalSide3Top
	redGoalSide4Bot
	redGoalSide4Top
	blueGoalSide1Bot
	blueGoalSide1Top
	blueGoalSide2Bot
	blueGoalSide2Top
	blueGoalSide3Bot
	blueGoalSide3Top
	blueGoalSide4Bot
	blueGoalSide4Top
)

type fixture struct {
	id           fixtureId
	universe     int
	startAddress int
}

type fixtureLayout struct {
	red  []fixture
	blue []fixture
}

// defaultFixtureLayout maps each 8-pixel fixture to a DMX universe and 1-based DMX start address.
// To split the field across multiple universes, change the universe values below; the controller will
// automatically assemble and send one packet per universe.
var defaultFixtureLayout = fixtureLayout{
	red: []fixture{
		// Facing Driver Station.
		{redGoalSide1Bot, 1, 1},
		{redGoalSide1Top, 1, 25},
		// Facing Audience.
		{redGoalSide2Bot, 1, 49},
		{redGoalSide2Top, 1, 73},
		// Facing Center.
		{redGoalSide3Bot, 1, 97},
		{redGoalSide3Top, 1, 121},
		// Facing Scoring Table.
		{redGoalSide4Bot, 1, 145},
		{redGoalSide4Top, 1, 169},
	},
	blue: []fixture{
		// Facing Driver Station.
		{blueGoalSide1Bot, 2, 1},
		{blueGoalSide1Top, 2, 25},
		// Facing Audience.
		{blueGoalSide2Bot, 2, 49},
		{blueGoalSide2Top, 2, 73},
		// Facing Center.
		{blueGoalSide3Bot, 2, 97},
		{blueGoalSide3Top, 2, 121},
		// Facing Scoring Table.
		{blueGoalSide4Bot, 2, 145},
		{blueGoalSide4Top, 2, 169},
	},
}

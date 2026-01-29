package db

import (
	"time"
)

type Node struct {
	ID        uint      `gorm:"primaryKey"`
	Name      string    `gorm:"type:text"`
	URL       string    `gorm:"type:text"`
	Enabled   bool      `gorm:"default:false"`
	APIKey    string    `gorm:"size:255"`
	LastCheck *time.Time
}

func (Node) TableName() string {
	return "node"
}

type Task struct {
	ID             uint      `gorm:"primaryKey"`
	Path           string    `gorm:"type:text"`
	Category       string    `gorm:"type:text"`
	Package        string    `gorm:"type:text"`
	Timeout        int
	Priority       int
	Options        string    `gorm:"type:text"`
	Machine        string    `gorm:"type:text"`
	Platform       string    `gorm:"type:text"`
	Route          string    `gorm:"type:text"`
	Tags           string    `gorm:"type:text"`
	Custom         string    `gorm:"type:text"`
	Memory         string    `gorm:"type:text"`
	Clock          time.Time `gorm:"default:CURRENT_TIMESTAMP"`
	EnforceTimeout string    `gorm:"type:text"`
	TLP            string    `gorm:"type:text"`

	NodeID     uint `gorm:"index"`
	TaskID     uint `gorm:"index"`     // ID on the worker node
	MainTaskID uint `gorm:"index"` // ID on the master node

	Finished    bool `gorm:"default:false"`
	Retrieved   bool `gorm:"default:false"`
	Notificated bool `gorm:"default:false"`
	Deleted     bool `gorm:"default:false"`
}

func (Task) TableName() string {
	return "task"
}

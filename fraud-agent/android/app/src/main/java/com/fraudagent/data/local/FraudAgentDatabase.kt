package com.fraudagent.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(
    entities = [DetectionEntity::class, ReportEntity::class],
    version = 1,
    exportSchema = false
)
abstract class FraudAgentDatabase : RoomDatabase() {
    abstract fun detectionDao(): DetectionDao
    abstract fun reportDao(): ReportDao

    companion object {
        @Volatile
        private var INSTANCE: FraudAgentDatabase? = null

        fun getDatabase(context: Context): FraudAgentDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    FraudAgentDatabase::class.java,
                    "fraud_agent_database"
                )
                    .fallbackToDestructiveMigration()
                    .build()
                INSTANCE = instance
                instance
            }
        }
    }
}
package com.strykerx.lab.core.database

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(
    entities = [
        TargetEntity::class,
        ScopeEntity::class,
        ScanSessionEntity::class,
        FindingEntity::class,
        ErrorLogEntity::class
    ],
    version = 1,
    exportSchema = false
)
abstract class StrykerDatabase : RoomDatabase() {
    abstract fun targetDao(): TargetDao
    abstract fun scopeDao(): ScopeDao
    abstract fun scanSessionDao(): ScanSessionDao
    abstract fun findingDao(): FindingDao
    abstract fun errorLogDao(): ErrorLogDao

    companion object {
        @Volatile
        private var INSTANCE: StrykerDatabase? = null

        fun get(context: Context): StrykerDatabase =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: Room.databaseBuilder(
                    context.applicationContext,
                    StrykerDatabase::class.java,
                    "stryker-x.db"
                )
                    // Future schema versions register migrations here; see
                    // ARCHITECTURE.md. No destructive fallback in production.
                    .build()
                    .also { INSTANCE = it }
            }
    }
}

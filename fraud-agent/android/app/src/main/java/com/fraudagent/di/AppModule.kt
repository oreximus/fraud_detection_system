package com.fraudagent.di

import android.content.Context
import com.fraudagent.data.local.*
import com.fraudagent.data.repository.DetectionRepositoryImpl
import com.fraudagent.data.repository.ReportRepositoryImpl
import com.fraudagent.domain.repository.DetectionRepository
import com.fraudagent.domain.repository.ReportRepository
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {
    
    @Provides
    @Singleton
    fun provideDatabase(
        @ApplicationContext context: Context
    ): FraudAgentDatabase {
        return FraudAgentDatabase.getDatabase(context)
    }
    
    @Provides
    @Singleton
    fun provideDetectionDao(database: FraudAgentDatabase): DetectionDao {
        return database.detectionDao()
    }
    
    @Provides
    @Singleton
    fun provideReportDao(database: FraudAgentDatabase): ReportDao {
        return database.reportDao()
    }
}

@Module
@InstallIn(SingletonComponent::class)
abstract class RepositoryModule {
    
    @Binds
    @Singleton
    abstract fun bindDetectionRepository(
        impl: DetectionRepositoryImpl
    ): DetectionRepository
    
    @Binds
    @Singleton
    abstract fun bindReportRepository(
        impl: ReportRepositoryImpl
    ): ReportRepository
}
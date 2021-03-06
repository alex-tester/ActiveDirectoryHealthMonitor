USE [{0}]

/****** Object:  Table [dbo].[AdAuthFailures]    Script Date: 12/25/2020 7:43:01 AM ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[AdAuthFailures](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[CreatedOn] [datetime] NOT NULL,
	[CreatedBy] [varchar](50) NOT NULL,
	[ModifiedOn] [datetime] NOT NULL,
	[ModifiedBy] [varchar](50) NOT NULL,
	[EventId] [int] NOT NULL,
	[AuthPackage] [varchar](200) NULL,
	[Account] [varchar](100) NULL,
	[SourceWorkstation] [varchar](100) NULL,
	[ErrorCode] [varchar](100) NULL,
	[EntryType] [varchar](50) NULL,
	[Realm] [varchar](100) NULL,
	[SID] [varchar](100) NULL,
	[TicketOptions] [varchar](100) NULL,
	[ResultCode] [varchar](100) NULL,
PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

/****** Object:  Table [dbo].[AdAuthFailures]    Script Date: 12/25/2020 7:43:01 AM ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[ExecutionHistory](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[CreatedOn] [datetime] NOT NULL,
	[CreatedBy] [varchar](50) NOT NULL,
	[ModifiedOn] [datetime] NOT NULL,
	[ModifiedBy] [varchar](50) NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

/****** Object:  Table [dbo].[AdDcToSites]    Script Date: 12/25/2020 7:43:01 AM ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[AdDcToSites](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[CreatedOn] [datetime] NOT NULL,
	[CreatedBy] [varchar](50) NOT NULL,
	[ModifiedOn] [datetime] NOT NULL,
	[ModifiedBy] [varchar](50) NOT NULL,
	[DomainControllerId] [int] NOT NULL,
	[SiteId] [int] NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

/****** Object:  Table [dbo].[AdDomainControllerDcDiagResults]    Script Date: 12/25/2020 7:43:01 AM ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[AdDomainControllerDcDiagResults](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[ExecutionID] [int] NOT NULL,
	[CreatedOn] [datetime] NOT NULL,
	[CreatedBy] [varchar](50) NOT NULL,
	[ModifiedOn] [datetime] NOT NULL,
	[ModifiedBy] [varchar](50) NOT NULL,
	[DomainControllerId] [int] NOT NULL,
	[Server] [varchar](50) NULL,
	[TestName] [varchar](100) NOT NULL,
	[TestPassed] [bit] NOT NULL,
	[TestItem] [varchar](100) NOT NULL,
	[ExtendedDetails] [text] NULL,
PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

/****** Object:  Table [dbo].[AdDomainControllers]    Script Date: 12/25/2020 7:43:01 AM ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[AdDomainControllers](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[CreatedOn] [datetime] NOT NULL,
	[CreatedBy] [varchar](50) NOT NULL,
	[ModifiedOn] [datetime] NOT NULL,
	[ModifiedBy] [varchar](50) NOT NULL,
	[DomainId] [int] NOT NULL,
	[DNSHostName] [varchar](50) NULL,
	[Name] [varchar](50) NOT NULL,
	[SID] [varchar](50) NOT NULL,
	[ObjectGUID] [varchar](50) NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

/****** Object:  Table [dbo].[AdDomains]    Script Date: 12/25/2020 7:43:01 AM ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[AdDomains](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[CreatedOn] [datetime] NOT NULL,
	[CreatedBy] [varchar](50) NOT NULL,
	[ModifiedOn] [datetime] NOT NULL,
	[ModifiedBy] [varchar](50) NOT NULL,
	[ForestId] [int] NOT NULL,
	[DomainMode] [varchar](50) NOT NULL,
	[Name] [varchar](100) NOT NULL,
	[InfrastructureMaster] [varchar](50) NOT NULL,
	[DomainSID] [varchar](50) NOT NULL,
	[ObjectGUID] [varchar](50) NOT NULL,
	[PDCEmulator] [varchar](50) NOT NULL,
	[RIDMaster] [varchar](50) NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

/****** Object:  Table [dbo].[AdForests]    Script Date: 12/25/2020 7:43:01 AM ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[AdForests](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[CreatedOn] [datetime] NOT NULL,
	[CreatedBy] [varchar](50) NOT NULL,
	[ModifiedOn] [datetime] NOT NULL,
	[ModifiedBy] [varchar](50) NOT NULL,
	[Name] [varchar](100) NOT NULL,
	[RootDomain] [varchar](100) NOT NULL,
	[DomainNamingMaster] [varchar](500) NOT NULL,
	[SchemaMaster] [varchar](50) NOT NULL,
	[ForestMode] [varchar](50) NOT NULL,
PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

/****** Object:  Table [dbo].[AdSites]    Script Date: 12/25/2020 7:43:01 AM ******/
SET ANSI_NULLS ON

SET QUOTED_IDENTIFIER ON

CREATE TABLE [dbo].[AdSites](
	[id] [int] IDENTITY(1,1) NOT NULL,
	[CreatedOn] [datetime] NOT NULL,
	[CreatedBy] [varchar](50) NOT NULL,
	[ModifiedOn] [datetime] NOT NULL,
	[ModifiedBy] [varchar](50) NOT NULL,
	[ForestId] [int] NOT NULL,
	[InterSiteTopologyGenerator] [varchar](50) NULL,
	[Name] [varchar](50) NOT NULL,
	[Options] [varchar](500) NULL,
	[Location] [varchar](200) NULL,
PRIMARY KEY CLUSTERED 
(
	[id] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON) ON [PRIMARY]
) ON [PRIMARY]

ALTER TABLE [dbo].[AdDcToSites]  WITH CHECK ADD  CONSTRAINT [FK_AdDcToSites_AdDomainControllers] FOREIGN KEY([DomainControllerId])
REFERENCES [dbo].[AdDomainControllers] ([id])

ALTER TABLE [dbo].[AdDcToSites] CHECK CONSTRAINT [FK_AdDcToSites_AdDomainControllers]

ALTER TABLE [dbo].[AdDcToSites]  WITH CHECK ADD  CONSTRAINT [FK_AdDcToSites_AdSites] FOREIGN KEY([SiteId])
REFERENCES [dbo].[AdSites] ([id])

ALTER TABLE [dbo].[AdDcToSites] CHECK CONSTRAINT [FK_AdDcToSites_AdSites]

ALTER TABLE [dbo].[AdDomainControllerDcDiagResults]  WITH CHECK ADD  CONSTRAINT [FK_AdDomainControllerDcDiagResults_AdDomainControllers] FOREIGN KEY([DomainControllerId])
REFERENCES [dbo].[AdDomainControllers] ([id])

ALTER TABLE [dbo].[AdDomainControllerDcDiagResults] CHECK CONSTRAINT [FK_AdDomainControllerDcDiagResults_AdDomainControllers]

ALTER TABLE [dbo].[AdDomainControllers]  WITH CHECK ADD  CONSTRAINT [FK_AdDomainControllers_AdDomains] FOREIGN KEY([DomainId])
REFERENCES [dbo].[AdDomains] ([id])

ALTER TABLE [dbo].[AdDomainControllers] CHECK CONSTRAINT [FK_AdDomainControllers_AdDomains]

ALTER TABLE [dbo].[AdDomains]  WITH CHECK ADD  CONSTRAINT [FK_AdDomains_AdForests] FOREIGN KEY([ForestId])
REFERENCES [dbo].[AdForests] ([id])

ALTER TABLE [dbo].[AdDomains] CHECK CONSTRAINT [FK_AdDomains_AdForests]

ALTER TABLE [dbo].[AdSites]  WITH CHECK ADD  CONSTRAINT [FK_AdSites_AdForests] FOREIGN KEY([ForestId])
REFERENCES [dbo].[AdForests] ([id])

ALTER TABLE [dbo].[AdSites] CHECK CONSTRAINT [FK_AdSites_AdForests]


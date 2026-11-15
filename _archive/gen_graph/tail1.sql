        /* 4.3 Türetilmiş aktör-aktör kenarı */
        EXEC dbo.sp_RefreshActorSimilarity;

        COMMIT TRANSACTION;
    END TRY
    BEGIN CATCH
        IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION;
        THROW;
    END CATCH;
END;
GO

/* İki modelin sayıca tutarlı olduğunu doğrular: her satırda Relational = Graph olmalı */
CREATE OR ALTER PROCEDURE dbo.sp_CheckGraphConsistency
AS
BEGIN
    SET NOCOUNT ON;
    SELECT x.ObjectName, x.Kind, x.Relational, x.Graph, CAST(CASE WHEN x.Relational = x.Graph THEN 1 ELSE 0 END AS BIT) AS IsConsistent
    FROM (

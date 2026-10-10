static class ReadyToRunInstanceMethodsTests
{
    public static void Run()
    {
        Test.Run("empty instance method hashtable", () =>
            Test.Equal(0, ReadyToRunInstanceMethods.Read([0, 0, 0]).Count));
        Test.Run("truncated instance method hashtable", () =>
            Test.Throws<BadImageFormatException>(() => ReadyToRunInstanceMethods.Read([])));
        Test.Run("truncated instance method bucket table", () =>
            Test.Throws<BadImageFormatException>(() => ReadyToRunInstanceMethods.Read([0, 0])));
    }
}

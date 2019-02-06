using System;
using Xunit;

namespace OSVersionHelper.Tests
{
    public class WindowsVersionTests
    {
        [Fact(Skip ="CI")]
        public void CurrentVersionReturnsCorrectly()
        {
            var currentVersion = WindowsVersionHelper.Windows10Release;

            Assert.Equal(Windows10Release.October2018, currentVersion);
        }
    }
}

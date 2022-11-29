package ossf.fuzz.introspector.soot;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import soot.SceneTransformer;

public class CustomSenceTransformerTest {
  @Test
  public void testNoException() {
    assertDoesNotThrow(() -> {});
  }

  @Test
  public void testBasic() {
    CustomSenceTransformer custom = new CustomSenceTransformer("", "", "");
    assertTrue(custom instanceof SceneTransformer);
    assertTrue(custom instanceof CustomSenceTransformer);
    assertEquals(custom.getExcludeList().size(), 0);
  }

  @Test
  public void testExcludePrefix() {
    CustomSenceTransformer custom = new CustomSenceTransformer("", "", "abc:def:ghi");
    assertEquals(custom.getExcludeList().size(), 3);
    Object[] expected = {"abc", "def", "ghi"};
    assertArrayEquals(custom.getExcludeList().toArray(), expected);
  }
}
